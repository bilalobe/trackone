#!/usr/bin/env python3
"""Behavioral tests for trackone_core when the native extension is unavailable."""

from __future__ import annotations

import importlib
import sys

import pytest


def _clear_modules(prefix: str) -> None:
    for key in list(sys.modules):
        if key == prefix or key.startswith(prefix + "."):
            sys.modules.pop(key, None)


def test_trackone_core_imports_without_native_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    # Force native import failure even if the extension is installed in the env.
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    tc = importlib.import_module("trackone_core")

    assert tc.__version__ == "0.0.0"
    assert tc._native is None  # type: ignore[attr-defined]
    assert tc.radio is not None  # type: ignore[attr-defined]

    with pytest.raises(ImportError, match=r"Native extension not available"):
        _ = tc.Gateway  # type: ignore[attr-defined]
    with pytest.raises(ImportError, match=r"Native extension not available"):
        _ = tc.GatewayBatch  # type: ignore[attr-defined]
    with pytest.raises(ImportError, match=r"Native extension not available"):
        _ = tc.PyRadio  # type: ignore[attr-defined]

    with pytest.raises(ImportError, match=r"Native extension not available"):
        _ = tc.radio.PyRadio  # type: ignore[attr-defined]


@pytest.mark.parametrize("submod", ["crypto", "ledger", "merkle", "ots"])
def test_shim_modules_raise_clear_importerror_when_native_missing(
    monkeypatch: pytest.MonkeyPatch, submod: str
) -> None:
    _clear_modules("trackone_core")
    # Force native import failure even if the extension is installed in the env.
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    # Importing the shim should succeed even without the native extension.
    m = importlib.import_module(f"trackone_core.{submod}")

    assert m.__all__ == []
    assert m.__dir__() == []
