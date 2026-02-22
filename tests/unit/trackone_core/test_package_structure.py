#!/usr/bin/env python3
"""Tests for trackone_core package structure and shim module imports.

These tests verify that:
- trackone_core can be imported when the native extension is available
- Shim modules (merkle, crypto, ledger, ots) correctly forward to _native submodules
- The radio shim forwards to _native directly (not a non-existent radio submodule)
- A failed radio import does not prevent the rest of the package from loading
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


def _make_mock_native() -> MagicMock:
    """Return a mock _native module with the expected top-level attributes."""
    native = MagicMock()
    native.__name__ = "trackone_core._native"
    native.__version__ = "0.1.0-test"
    native.__package__ = "trackone_core"

    # Top-level classes registered directly in _native (not as submodules)
    native.Gateway = MagicMock(name="Gateway")
    native.GatewayBatch = MagicMock(name="GatewayBatch")
    native.PyRadio = MagicMock(name="PyRadio")

    # Submodules registered via register() in Rust
    for sub in ("crypto", "ledger", "merkle", "ots"):
        setattr(native, sub, MagicMock(name=sub))

    return native


@pytest.fixture()
def mock_native(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Inject a mock _native module and clear stale trackone_core entries."""
    native = _make_mock_native()

    # Remove any already-imported trackone_core modules so tests get fresh imports
    for key in list(sys.modules):
        if key.startswith("trackone_core"):
            monkeypatch.delitem(sys.modules, key, raising=False)

    monkeypatch.setitem(sys.modules, "trackone_core._native", native)
    return native


# ---------------------------------------------------------------------------
# Package-level import
# ---------------------------------------------------------------------------


class TestPackageImport:
    """Verify trackone_core imports cleanly when the native extension is mocked."""

    def test_package_imports_successfully(self, mock_native: MagicMock) -> None:
        """trackone_core must be importable when _native is available."""
        import importlib

        tc = importlib.import_module("trackone_core")
        assert tc is not None

    def test_gateway_class_exposed(self, mock_native: MagicMock) -> None:
        """Gateway class should be re-exported at the top level."""
        import importlib

        tc = importlib.import_module("trackone_core")
        assert tc.Gateway is mock_native.Gateway

    def test_gateway_batch_class_exposed(self, mock_native: MagicMock) -> None:
        """GatewayBatch class should be re-exported at the top level."""
        import importlib

        tc = importlib.import_module("trackone_core")
        assert tc.GatewayBatch is mock_native.GatewayBatch

    def test_pyradio_class_exposed(self, mock_native: MagicMock) -> None:
        """PyRadio should be re-exported from the top-level _native, not a radio submodule."""
        import importlib

        tc = importlib.import_module("trackone_core")
        assert tc.PyRadio is mock_native.PyRadio

    def test_version_attribute(self, mock_native: MagicMock) -> None:
        """__version__ should be derived from _native."""
        import importlib

        tc = importlib.import_module("trackone_core")
        assert tc.__version__ == "0.1.0-test"

    def test_all_does_not_contain_radio(self, mock_native: MagicMock) -> None:
        """'radio' must not appear in __all__ (PyRadio is exported instead)."""
        import importlib

        tc = importlib.import_module("trackone_core")
        assert "radio" not in tc.__all__

    def test_all_contains_expected_submodules(self, mock_native: MagicMock) -> None:
        """__all__ should list the four stable shim submodules."""
        import importlib

        tc = importlib.import_module("trackone_core")
        for name in ("crypto", "ledger", "merkle", "ots"):
            assert name in tc.__all__, f"'{name}' missing from __all__"


# ---------------------------------------------------------------------------
# Shim submodule accessibility
# ---------------------------------------------------------------------------


class TestShimSubmodules:
    """Verify that the four shim modules can be imported and forward correctly."""

    @pytest.mark.parametrize("submod", ["crypto", "ledger", "merkle", "ots"])
    def test_submodule_accessible(
        self, mock_native: MagicMock, submod: str
    ) -> None:
        """Each shim submodule should be importable via trackone_core.<submod>."""
        import importlib

        m = importlib.import_module(f"trackone_core.{submod}")
        assert m is not None

    @pytest.mark.parametrize("submod", ["crypto", "ledger", "merkle", "ots"])
    def test_submodule_forwards_attributes(
        self, mock_native: MagicMock, submod: str
    ) -> None:
        """Attribute access on a shim submodule should delegate to _native.<submod>."""
        import importlib

        sentinel = MagicMock(return_value="sentinel-value")
        getattr(mock_native, submod).some_fn = sentinel

        m = importlib.import_module(f"trackone_core.{submod}")
        result = m.some_fn()
        assert result == "sentinel-value"


# ---------------------------------------------------------------------------
# Radio shim
# ---------------------------------------------------------------------------


class TestRadioShim:
    """Verify the radio shim uses _native directly (not a missing radio submodule)."""

    def test_radio_imports_without_error(self, mock_native: MagicMock) -> None:
        """trackone_core.radio should import without raising AttributeError."""
        import importlib

        radio = importlib.import_module("trackone_core.radio")
        assert radio is not None

    def test_radio_forwards_pyradio_from_native(self, mock_native: MagicMock) -> None:
        """PyRadio should be accessible via trackone_core.radio because the shim
        forwards to _native (not a non-existent _native.radio submodule)."""
        import importlib

        radio = importlib.import_module("trackone_core.radio")
        assert radio.PyRadio is mock_native.PyRadio

    def test_package_imports_even_if_radio_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken radio.py must not prevent the rest of the package from loading."""
        import importlib

        native = _make_mock_native()

        for key in list(sys.modules):
            if key.startswith("trackone_core"):
                monkeypatch.delitem(sys.modules, key, raising=False)

        monkeypatch.setitem(sys.modules, "trackone_core._native", native)

        # Setting sys.modules[name] = None causes Python's import machinery to raise
        # ImportError for that name, simulating a failed import without modifying files.
        # The type: ignore is needed because sys.modules is typed as dict[str, ModuleType]
        # but setting None is a documented Python idiom for negative module caching.
        monkeypatch.setitem(sys.modules, "trackone_core.radio", None)  # type: ignore[arg-type]

        tc = importlib.import_module("trackone_core")
        # Core package should still be importable; radio attribute should be None
        assert tc is not None
        assert tc.radio is None  # type: ignore[attr-defined]
