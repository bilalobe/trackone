from __future__ import annotations

import builtins
import importlib
import sys

import pytest


def _clear_peer_attestation_modules() -> None:
    for key in list(sys.modules):
        if key == "scripts.gateway.peer_attestation" or key.startswith("nacl."):
            sys.modules.pop(key, None)
    sys.modules.pop("nacl", None)


def test_peer_attestation_imports_without_pynacl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_peer_attestation_modules()
    try:
        real_import = builtins.__import__

        def _import_without_pynacl(
            name: str,
            globals=None,
            locals=None,
            fromlist=(),
            level: int = 0,
        ):
            if name == "nacl" or name.startswith("nacl."):
                raise ImportError("No module named 'nacl'")
            return real_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", _import_without_pynacl)
        for key in list(sys.modules):
            if key == "nacl" or key.startswith("nacl."):
                monkeypatch.delitem(sys.modules, key, raising=False)

        module = importlib.import_module("scripts.gateway.peer_attestation")

        with pytest.raises(module.PeerAttestationError, match="PyNaCl is required"):
            module.verify_peer_signature(
                site_id="an-001",
                day="2025-10-07",
                day_root_hex="ab" * 32,
                signature_hex="00" * 64,
                pubkey_hex="11" * 32,
            )
    finally:
        _clear_peer_attestation_modules()
