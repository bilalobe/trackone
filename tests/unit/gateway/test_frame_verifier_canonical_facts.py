from __future__ import annotations

import sys
from pathlib import Path

from scripts.gateway.input_integrity import write_sha256_sidecar


def test_frame_to_fact_emits_canonical_fields_only(load_module) -> None:
    frame_verifier = load_module(
        "frame_verifier_canonical_facts_under_test",
        Path("scripts/gateway/frame_verifier.py"),
    )

    frame = {
        "hdr": {"dev_id": 3, "msg_type": 1, "fc": 42, "flags": 0},
        "nonce": "abc123",
        "ct": "",
        "tag": "",
    }
    payload = {"counter": 42, "temp_c": 23.5}

    fact = frame_verifier.frame_to_fact(frame, payload)

    assert fact["pod_id"] == "0000000000000003"
    assert fact["fc"] == 42
    assert isinstance(fact["ingest_time"], int)
    assert fact["pod_time"] is None
    assert fact["kind"] == "Custom"
    assert fact["payload"] == payload

    assert fact["ingest_time_rfc3339_utc"].endswith("Z")
    assert "device_id" not in fact
    assert "nonce" not in fact
    assert "timestamp" not in fact


def test_frame_verifier_imports_without_pynacl(monkeypatch, load_module) -> None:
    for key in list(sys.modules):
        if key == "nacl" or key.startswith("nacl."):
            monkeypatch.delitem(sys.modules, key, raising=False)

    frame_verifier = load_module(
        "frame_verifier_import_without_pynacl_under_test",
        Path("scripts/gateway/frame_verifier.py"),
    )

    assert frame_verifier.aead_decrypt({}, {}) is None


def test_frame_verifier_process_reports_missing_pynacl(
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
        "_load_nacl_modules",
        lambda: (_ for _ in ()).throw(
            RuntimeError(
                "PyNaCl is required for framed AEAD verification paths. Install with: pip install PyNaCl"
            )
        ),
    )

    frames = tmp_path / "frames.ndjson"
    frames.write_text("", encoding="utf-8")
    facts = tmp_path / "facts"
    device_table = tmp_path / "device_table.json"
    device_table.write_text("{}", encoding="utf-8")
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
            ]
        )

    assert rc == 1
    assert "PyNaCl is required" in stderr.getvalue()
