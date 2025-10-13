#!/usr/bin/env python3
"""
Security/resilience tests for framed ingest:
- Tampered ciphertext should fail decryption
- Tampered tag should fail decryption
- Tampered AAD (dev_id/msg_type) should fail decryption
- Invalid nonce length should be rejected
- Unknown device_id (no key) should be rejected
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


GW_DIR = Path(__file__).parent.parent / "gateway"
frame_verifier = load_module("frame_verifier", GW_DIR / "frame_verifier.py")


@pytest.fixture
def temp_dirs(tmp_path):
    root = tmp_path / "site_demo"
    frames = root / "frames.ndjson"
    facts = root / "facts"
    device_table = root / "device_table.json"
    return {
        "root": root,
        "frames": frames,
        "facts": facts,
        "device_table": device_table,
    }


def write_frames(device_id: str, count: int, out_path: Path, device_table: Path):
    import subprocess

    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "scripts/pod_sim/pod_sim.py",
        "--device-id",
        device_id,
        "--count",
        str(count),
        "--framed",
        "--out",
        str(out_path),
        "--device-table",
        str(device_table),
    ]
    subprocess.run(cmd, check=True)


def verify(frames: Path, facts: Path, device_table: Path) -> int:
    args = [
        "--in",
        str(frames),
        "--out-facts",
        str(facts),
        "--device-table",
        str(device_table),
        "--window",
        "64",
    ]
    return frame_verifier.process(args)


class TestTamper:
    def test_tampered_ciphertext_rejected(self, temp_dirs):
        from base64 import b64decode, b64encode

        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-010", 1, temp_dirs["frames"], temp_dirs["device_table"])
        # Load, tamper ciphertext
        f = json.loads(temp_dirs["frames"].read_text(encoding="utf-8").splitlines()[0])
        b = bytearray(b64decode(f["ct"]))
        b[0] ^= 0x01
        f["ct"] = b64encode(bytes(b)).decode("ascii")
        temp_dirs["frames"].write_text(json.dumps(f) + "\n", encoding="utf-8")
        # Verify → expect 0 facts
        rc = verify(temp_dirs["frames"], temp_dirs["facts"], temp_dirs["device_table"])
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_tampered_tag_rejected(self, temp_dirs):
        from base64 import b64decode, b64encode

        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-011", 1, temp_dirs["frames"], temp_dirs["device_table"])
        f = json.loads(temp_dirs["frames"].read_text().strip())
        t = bytearray(b64decode(f["tag"]))
        t[0] ^= 0xFF
        f["tag"] = b64encode(bytes(t)).decode("ascii")
        temp_dirs["frames"].write_text(json.dumps(f) + "\n", encoding="utf-8")
        rc = verify(temp_dirs["frames"], temp_dirs["facts"], temp_dirs["device_table"])
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_tampered_aad_rejected(self, temp_dirs):
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-012", 1, temp_dirs["frames"], temp_dirs["device_table"])
        f = json.loads(temp_dirs["frames"].read_text().strip())
        # Change msg_type in header (affects AAD)
        f["hdr"]["msg_type"] ^= 0x01
        temp_dirs["frames"].write_text(json.dumps(f) + "\n", encoding="utf-8")
        rc = verify(temp_dirs["frames"], temp_dirs["facts"], temp_dirs["device_table"])
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_invalid_nonce_length_rejected(self, temp_dirs):
        from base64 import b64decode, b64encode

        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-013", 1, temp_dirs["frames"], temp_dirs["device_table"])
        f = json.loads(temp_dirs["frames"].read_text().strip())
        n = b64decode(f["nonce"])[:-1]  # drop a byte → 11 bytes
        f["nonce"] = b64encode(n).decode("ascii")
        temp_dirs["frames"].write_text(json.dumps(f) + "\n", encoding="utf-8")
        rc = verify(temp_dirs["frames"], temp_dirs["facts"], temp_dirs["device_table"])
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))

    def test_unknown_device_rejected(self, temp_dirs):
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-014", 1, temp_dirs["frames"], temp_dirs["device_table"])
        f = json.loads(temp_dirs["frames"].read_text().strip())
        # Change device id in header to a different one not present in device_table
        f["hdr"]["dev_id"] = 999
        temp_dirs["frames"].write_text(json.dumps(f) + "\n", encoding="utf-8")
        rc = verify(temp_dirs["frames"], temp_dirs["facts"], temp_dirs["device_table"])
        assert rc == 0
        assert not list(temp_dirs["facts"].glob("*.json"))
