from __future__ import annotations

import sys
import types
from pathlib import Path


def _ensure_fake_pynacl(monkeypatch) -> None:
    if "nacl" in sys.modules:
        return

    nacl = types.ModuleType("nacl")
    nacl_bindings = types.ModuleType("nacl.bindings")
    nacl_ex = types.ModuleType("nacl.exceptions")
    nacl.bindings = nacl_bindings  # type: ignore[attr-defined]
    nacl.exceptions = nacl_ex  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "nacl", nacl)
    monkeypatch.setitem(sys.modules, "nacl.bindings", nacl_bindings)
    monkeypatch.setitem(sys.modules, "nacl.exceptions", nacl_ex)


def test_frame_to_fact_emits_canonical_and_legacy_fields(
    load_module, monkeypatch
) -> None:
    _ensure_fake_pynacl(monkeypatch)
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

    # Transitional compatibility fields still present.
    assert fact["device_id"] == "pod-003"
    assert fact["nonce"] == "abc123"
    assert fact["timestamp"] == fact["ingest_time_rfc3339_utc"]
