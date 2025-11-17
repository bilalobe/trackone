from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from scripts.gateway import frame_verifier as fv


def _mk_device_table(tmp_path: Path) -> Path:
    # Include required _meta.master_seed and per-device salt8 to satisfy schema
    master_seed = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    ck = secrets.token_bytes(32)
    salt8 = base64.b64encode(secrets.token_bytes(8)).decode("ascii")
    tbl = {
        "_meta": {"version": "1.0", "master_seed": master_seed},
        "1": {
            "salt8": salt8,
            "ck_up": base64.b64encode(ck).decode("ascii"),
            "highest_fc_seen": -1,
        },
    }
    p = tmp_path / "device_table.json"
    p.write_text(json.dumps(tbl, indent=2), encoding="utf-8")
    return p


def _encrypt_payload(
    ck: bytes, dev_id: int, msg_type: int, payload: bytes
) -> tuple[str, str, str]:
    aad = (dev_id & 0xFFFF).to_bytes(2, "big") + (msg_type & 0xFF).to_bytes(1, "big")
    nonce = secrets.token_bytes(24)
    ct_tag = fv.nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        payload, aad, nonce, ck
    )
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return (
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(ct).decode("ascii"),
        base64.b64encode(tag).decode("ascii"),
    )


def _mk_frame(ck: bytes, dev_id: int, fc: int, msg_type: int = 1) -> dict[str, Any]:
    payload = (
        b"\x01\x04"
        + fc.to_bytes(4, "big")
        + b"\x03\x02"  # counter
        + (2500).to_bytes(2, "big", signed=True)
        + b"\x02\x02"  # temp 25.00
        + (1234).to_bytes(2, "big")  # bioimpedance 12.34
    )
    nonce_b64, ct_b64, tag_b64 = _encrypt_payload(ck, dev_id, msg_type, payload)
    return {
        "hdr": {"dev_id": dev_id, "msg_type": msg_type, "fc": fc, "flags": 0},
        "nonce": nonce_b64,
        "ct": ct_b64,
        "tag": tag_b64,
    }


@pytest.mark.parametrize("fc", [1, 2, 64, 128])
def test_parse_and_decrypt_frame(benchmark, tmp_path: Path, fc: int):
    # Arrange device table and key material
    dev_id = 1
    # Create a schema-compliant device table and get the ck from it
    device_table_path = _mk_device_table(tmp_path)
    # extract ck for frame creation
    dt = json.loads(device_table_path.read_text(encoding="utf-8"))
    ck = base64.b64decode(dt["1"]["ck_up"])
    device_table = fv.load_device_table(device_table_path)

    frame = _mk_frame(ck, dev_id, fc)
    line = json.dumps(frame)

    def fn() -> dict[str, Any] | None:
        parsed, err = fv.parse_frame(line)
        assert parsed is not None and err == ""
        return fv.aead_decrypt(parsed, device_table)

    payload = benchmark(fn)
    assert isinstance(payload, dict) and payload.get("counter") == fc


def test_end_to_end_process_small_batch(benchmark, tmp_path: Path):
    # Prepare synthetic device, frames, and IO paths
    dev_id = 1
    device_table_path = _mk_device_table(tmp_path)
    dt = json.loads(device_table_path.read_text(encoding="utf-8"))
    ck = base64.b64decode(dt["1"]["ck_up"])

    frames = [_mk_frame(ck, dev_id, fc) for fc in range(1, 6)]
    frames_path = tmp_path / "frames.ndjson"
    frames_path.write_text(
        "\n".join(json.dumps(f) for f in frames) + "\n", encoding="utf-8"
    )

    out_facts = tmp_path / "facts"

    def fn() -> int:
        return fv.process(
            [
                "--in",
                str(frames_path),
                "--out-facts",
                str(out_facts),
                "--device-table",
                str(device_table_path),
                "--window",
                "64",
            ]
        )

    rc = benchmark(fn)
    assert rc == 0
    files = sorted(out_facts.glob("*.json"))
    assert len(files) == 5
