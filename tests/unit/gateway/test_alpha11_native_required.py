from __future__ import annotations

import importlib
import sys

import pytest


def _clear_modules(prefix: str) -> None:
    for key in list(sys.modules):
        if key == prefix or key.startswith(prefix + "."):
            sys.modules.pop(key, None)


def test_input_integrity_import_fails_without_native_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    _clear_modules("scripts.gateway.input_integrity")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    try:
        with pytest.raises(ImportError, match="Native extension not available"):
            importlib.import_module("scripts.gateway.input_integrity")
    finally:
        _clear_modules("trackone_core")
        _clear_modules("scripts.gateway.input_integrity")
