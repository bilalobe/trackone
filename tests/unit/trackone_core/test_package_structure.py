#!/usr/bin/env python3
"""Tests for trackone_core package structure and shim module imports.

These tests verify that:
- trackone_core can be imported when the native extension is available
- Shim modules (`merkle`, `crypto`, `ledger`, `ots`) correctly forward to `_native` submodules
- The radio shim forwards to _native directly (not a non-existent radio submodule)
- A failed radio import does not prevent the rest of the package from loading
"""

from __future__ import annotations

import sys
from types import ModuleType
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
    native.crypto.ReplayWindowState = MagicMock(name="ReplayWindowState")

    return native


def _clear_trackone_core_modules() -> None:
    for key in list(sys.modules):
        if key.startswith("trackone_core"):
            sys.modules.pop(key, None)


@pytest.fixture()
def mock_native(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Inject a mock _native module and clear stale trackone_core entries."""
    native = _make_mock_native()

    _clear_trackone_core_modules()

    monkeypatch.setitem(sys.modules, "trackone_core._native", native)
    try:
        yield native
    finally:
        _clear_trackone_core_modules()


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
        """__all__ should list the stable shim submodules."""
        import importlib

        tc = importlib.import_module("trackone_core")
        for name in (
            "crypto",
            "ledger",
            "merkle",
            "ots",
            "release",
            "sensorthings",
            "verification",
        ):
            assert name in tc.__all__, f"'{name}' missing from __all__"


# ---------------------------------------------------------------------------
# Shim submodule accessibility
# ---------------------------------------------------------------------------


class TestShimSubmodules:
    """Verify that the shim modules can be imported and forward correctly."""

    def test_ots_shim_tolerates_legacy_native_surface(
        self, mock_native: MagicMock
    ) -> None:
        """Import should succeed when _native.ots lacks the new class exports."""
        import importlib

        legacy_ots = ModuleType("ots")
        legacy_ots.verify_ots_proof = MagicMock(name="verify_ots_proof")
        legacy_ots.validate_meta_sidecar = MagicMock(name="validate_meta_sidecar")
        mock_native.ots = legacy_ots

        tc = importlib.import_module("trackone_core")
        ots = importlib.import_module("trackone_core.ots")

        assert tc is not None
        assert ots.verify_ots_proof is legacy_ots.verify_ots_proof
        assert not hasattr(ots, "OtsStatus")

    @pytest.mark.parametrize("submod", ["crypto", "ledger", "merkle", "ots"])
    def test_submodule_accessible(self, mock_native: MagicMock, submod: str) -> None:
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

    def test_crypto_shim_exposes_validate_and_decrypt_framed(
        self, mock_native: MagicMock
    ) -> None:
        """The crypto shim should expose the native framed-ingest helper."""
        import importlib

        sentinel = MagicMock(return_value=({"counter": 1}, None))
        mock_native.crypto.validate_and_decrypt_framed = sentinel

        crypto = importlib.import_module("trackone_core.crypto")
        payload, reason = crypto.validate_and_decrypt_framed({}, {})

        assert payload == {"counter": 1}
        assert reason is None
        sentinel.assert_called_once()

    def test_crypto_shim_exposes_admit_framed_fact(
        self, mock_native: MagicMock
    ) -> None:
        """The crypto shim should expose the native admitted-fact helper."""
        import importlib

        sentinel = MagicMock(return_value=({"fc": 1}, None, None))
        mock_native.crypto.admit_framed_fact = sentinel

        crypto = importlib.import_module("trackone_core.crypto")
        fact, reason, source = crypto.admit_framed_fact(
            {},
            {},
            object(),
            ingest_time=1,
            ingest_time_rfc3339_utc="2026-01-01T00:00:01Z",
        )

        assert fact == {"fc": 1}
        assert reason is None
        assert source is None
        sentinel.assert_called_once()


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

        _clear_trackone_core_modules()

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
        _clear_trackone_core_modules()
