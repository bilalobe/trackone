#!/usr/bin/env python3
"""Tests for selecting the packaged Rust acceleration module.

The supported layout is `trackone_core` as a Python package with the native
module at `trackone_core._native`.
"""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest


def _clear_modules(prefix: str) -> None:
    for key in list(sys.modules):
        if key == prefix or key.startswith(prefix + "."):
            sys.modules.pop(key, None)


def _ensure_fake_pynacl(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure imports succeed on minimal environments without PyNaCl installed.

    Some scripts import `nacl.*` at module import time. These tests are about
    Rust-module selection logic, so a tiny stub is sufficient.
    """
    if "nacl" in sys.modules:
        return

    nacl = types.ModuleType("nacl")
    nacl_ex = types.ModuleType("nacl.exceptions")
    nacl_enc = types.ModuleType("nacl.encoding")
    nacl_sign = types.ModuleType("nacl.signing")

    class BadSignatureError(Exception):
        pass

    class HexEncoder:  # pragma: no cover - import-time stub
        pass

    class SigningKey:  # pragma: no cover - import-time stub
        def __init__(self, *_args, **_kwargs) -> None:
            raise RuntimeError("stub")

    class VerifyKey:  # pragma: no cover - import-time stub
        def __init__(self, *_args, **_kwargs) -> None:
            raise RuntimeError("stub")

    nacl_ex.BadSignatureError = BadSignatureError  # type: ignore[attr-defined]
    nacl_enc.HexEncoder = HexEncoder  # type: ignore[attr-defined]
    nacl_sign.SigningKey = SigningKey  # type: ignore[attr-defined]
    nacl_sign.VerifyKey = VerifyKey  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "nacl", nacl)
    monkeypatch.setitem(sys.modules, "nacl.exceptions", nacl_ex)
    monkeypatch.setitem(sys.modules, "nacl.encoding", nacl_enc)
    monkeypatch.setitem(sys.modules, "nacl.signing", nacl_sign)


@pytest.mark.parametrize(
    ("script_mod", "shim_names"),
    [
        ("scripts.gateway.merkle_batcher", ("merkle", "ledger")),
        (
            "scripts.gateway.verify_cli",
            ("merkle", "ledger", "ots"),
        ),
    ],
)
def test_packaged_layout_prefers_trackone_core_public_shims(
    monkeypatch: pytest.MonkeyPatch, script_mod: str, shim_names: tuple[str, ...]
) -> None:
    _ensure_fake_pynacl(monkeypatch)
    _clear_modules("trackone_core")
    _clear_modules("scripts.gateway")

    native = MagicMock()
    native.merkle = MagicMock(name="merkle")
    native.ledger = MagicMock(name="ledger")
    native.ots = MagicMock(name="ots")
    monkeypatch.setitem(sys.modules, "trackone_core._native", native)

    # Import the real package from the checkout; it will pick up our mocked _native.
    tc = importlib.import_module("trackone_core")
    assert tc._native is native

    m = importlib.import_module(script_mod)
    m = importlib.reload(m)

    merkle_mod = importlib.import_module("trackone_core.merkle")
    ledger_mod = importlib.import_module("trackone_core.ledger")
    ots_mod = importlib.import_module("trackone_core.ots")

    for attr in shim_names:
        if attr == "ots":
            assert getattr(m, attr) is ots_mod
        elif attr == "merkle":
            assert getattr(m, attr) is merkle_mod
        elif attr == "ledger":
            assert getattr(m, attr) is ledger_mod

    assert not hasattr(m, "native_ledger")
    assert not hasattr(m, "native_merkle")
    assert not hasattr(m, "native_ots")
