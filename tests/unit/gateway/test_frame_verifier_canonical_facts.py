from __future__ import annotations

import sys
from pathlib import Path

from scripts.gateway.input_integrity import write_sha256_sidecar


def test_frame_verifier_imports_without_pynacl(monkeypatch, load_module) -> None:
    for key in list(sys.modules):
        if key == "nacl" or key.startswith("nacl."):
            monkeypatch.delitem(sys.modules, key, raising=False)

    frame_verifier = load_module(
        "frame_verifier_import_without_pynacl_under_test",
        Path("scripts/gateway/frame_verifier.py"),
    )

    assert frame_verifier.aead_decrypt({}, {}) is None


def test_frame_verifier_process_reports_missing_native_crypto_for_rust_postcard(
    monkeypatch, load_module, tmp_path
) -> None:
    import contextlib
    import io

    frame_verifier = load_module(
        "frame_verifier_process_without_pynacl_under_test",
        Path("scripts/gateway/frame_verifier.py"),
    )
    monkeypatch.setattr(
        frame_verifier,
        "_load_native_crypto",
        lambda: (_ for _ in ()).throw(
            RuntimeError(
                "trackone_core native crypto helper is required for framed AEAD verification paths. Build/install the native extension or run via tox."
            )
        ),
    )

    frames = tmp_path / "frames.ndjson"
    frames.write_text(
        '{"hdr":{"dev_id":1,"msg_type":1,"fc":0,"flags":0},"nonce":"c3Nzc3Nzc3MAAAAAAAAAAFJSUlJSUlJS","ct":"AA==","tag":"AAAAAAAAAAAAAAAAAAAAAA=="}\n',
        encoding="utf-8",
    )
    facts = tmp_path / "facts"
    device_table = tmp_path / "device_table.json"
    device_table.write_text(
        '{"_meta":{"version":"1.0","master_seed":"bW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0="},"1":{"salt8":"c3Nzc3Nzc3M=","ck_up":"a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="}}',
        encoding="utf-8",
    )
    write_sha256_sidecar(device_table)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        rc = frame_verifier.process(
            [
                "--in",
                str(frames),
                "--out-facts",
                str(facts),
                "--device-table",
                str(device_table),
                "--ingest-profile",
                frame_verifier.DEFAULT_INGEST_PROFILE,
            ]
        )

    assert rc == 1
    assert "trackone_core native crypto helper is required" in stderr.getvalue()


def test_frame_verifier_process_reports_missing_native_ledger(
    monkeypatch, load_module, tmp_path
) -> None:
    import contextlib
    import io

    frame_verifier = load_module(
        "frame_verifier_process_without_native_ledger_under_test",
        Path("scripts/gateway/frame_verifier.py"),
    )
    monkeypatch.setattr(
        frame_verifier,
        "_admit_framed_fact",
        lambda _frame, _device_table, _replay_states, *, window_size, ingest_time, ingest_time_rfc3339_utc, ingest_profile: (
            {
                "pod_id": "0000000000000001",
                "fc": 0,
                "ingest_time": ingest_time,
                "pod_time": None,
                "kind": "custom.raw",
                "payload": {"counter": 1, "temp_c": 23.5},
                "ingest_time_rfc3339_utc": ingest_time_rfc3339_utc,
            },
            "",
            "",
        ),
    )
    monkeypatch.setattr(
        frame_verifier,
        "canonicalize_obj_to_cbor_native",
        lambda _obj: (_ for _ in ()).throw(
            RuntimeError(
                "trackone_core native ledger helper is required for authoritative commitment paths. Build/install the native extension or run via tox."
            )
        ),
    )

    frames = tmp_path / "frames.ndjson"
    frames.write_text(
        '{"hdr":{"dev_id":1,"msg_type":1,"fc":0,"flags":0},"nonce":"c3Nzc3Nzc3MAAAAAAAAAAFJSUlJSUlJS","ct":"AA==","tag":"AAAAAAAAAAAAAAAAAAAAAA=="}\n',
        encoding="utf-8",
    )
    facts = tmp_path / "facts"
    device_table = tmp_path / "device_table.json"
    device_table.write_text(
        '{"_meta":{"version":"1.0","master_seed":"bW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0="}}',
        encoding="utf-8",
    )
    write_sha256_sidecar(device_table)

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        rc = frame_verifier.process(
            [
                "--in",
                str(frames),
                "--out-facts",
                str(facts),
                "--device-table",
                str(device_table),
                "--ingest-profile",
                frame_verifier.DEFAULT_INGEST_PROFILE,
            ]
        )

    assert rc == 1
    assert "trackone_core native ledger helper is required" in stderr.getvalue()
