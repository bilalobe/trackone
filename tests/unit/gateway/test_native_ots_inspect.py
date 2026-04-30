from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


def _load_helper():
    script = (
        Path(__file__).resolve().parents[3] / "scripts" / "ci" / "native_ots_inspect.py"
    )
    spec = importlib.util.spec_from_file_location("native_ots_inspect", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_ots_inspect_extracts_bitcoin_attestation_height(tmp_path):
    helper = _load_helper()
    ots_path = tmp_path / "proof.ots"
    ots_path.write_bytes(b"proof")
    fake_ots = SimpleNamespace(
        describe_ots_proof=lambda *_args: [
            "append deadbeef",
            "sha256",
            "verify BitcoinBlockHeaderAttestation(849123)",
        ]
    )

    result = helper.inspect_root(tmp_path, fake_ots)

    assert result["heights"] == [849123]
    assert result["files"][0]["status"] == "native_parsed"
    assert result["files"][0]["stage"] == "headers_wait_block_sync"
    assert result["files"][0]["next_trigger"] == "sync-blocks"


def test_native_ots_inspect_classifies_pending_attestation(tmp_path):
    helper = _load_helper()
    ots_path = tmp_path / "proof.ots"
    ots_path.write_bytes(b"proof")
    fake_ots = SimpleNamespace(
        describe_ots_proof=lambda *_args: [
            "prepend cafebabe",
            "sha256",
            "verify PendingAttestation(https://calendar.example)",
        ]
    )

    result = helper.inspect_root(tmp_path, fake_ots)

    assert result["heights"] == []
    assert result["files"][0]["status"] == "native_parsed"
    assert result["files"][0]["stage"] == "calendar_pending"
    assert result["files"][0]["next_trigger"] == "upgrade"


def test_native_ots_inspect_reports_native_unsupported(tmp_path):
    helper = _load_helper()
    ots_path = tmp_path / "proof.ots"
    ots_path.write_bytes(b"proof")

    def raise_unsupported(*_args):
        raise ValueError("ots-proof-unsupported")

    fake_ots = SimpleNamespace(describe_ots_proof=raise_unsupported)

    result = helper.inspect_root(tmp_path, fake_ots)

    assert result["heights"] == []
    assert result["files"][0]["status"] == "native_unsupported"
    assert result["files"][0]["stage"] == "unknown"
    assert result["files"][0]["next_trigger"] == "ots-info"
