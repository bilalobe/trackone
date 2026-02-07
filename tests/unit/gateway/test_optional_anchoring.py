"""Tests for optional anchoring / lazy `requests` behavior.

These tests assert that:
- `get_requests()` surfaces a clear RuntimeError when `requests` is missing.
- `request_tsa()` propagates that RuntimeError when called without `requests`.
- When `requests` is present, `get_requests()` simply returns the module.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def clear_requests_from_sys_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure `requests` is absent or can be controlled for each test."""

    for name in list(sys.modules):
        if name == "requests" or name.startswith("requests."):
            monkeypatch.delitem(sys.modules, name, raising=False)


def test_require_requests_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    utils_mod = importlib.import_module("scripts.gateway.tsa_utils")

    # Remove requests from sys.modules to ensure clean state
    for name in list(sys.modules):
        if name == "requests" or name.startswith("requests."):
            del sys.modules[name]

    # Patch builtins.__import__ to raise ModuleNotFoundError for 'requests'
    original_import = builtins.__import__

    def custom_import(name, *args, **kwargs):  # type: ignore
        if name == "requests":
            raise ModuleNotFoundError("No module named 'requests'")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", custom_import)

    with pytest.raises(
        RuntimeError, match="Anchoring features require the 'requests' package"
    ):
        utils_mod._require_requests()  # type: ignore[attr-defined]


def test_require_requests_returns_module_when_present(
    clear_requests_from_sys_modules: None,
) -> None:
    pytest.importorskip("requests")

    utils_mod = importlib.import_module("scripts.gateway.tsa_utils")
    requests_mod = utils_mod._require_requests()  # type: ignore[attr-defined]

    assert getattr(requests_mod, "__name__", "") == "requests"
    assert hasattr(requests_mod, "post")


def test_request_tsa_propagates_runtimeerror_when_missing_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_mod = importlib.import_module("scripts.gateway.tsa_http_client")

    def fake_require_requests():
        raise RuntimeError("Anchoring features require the 'requests' package")

    monkeypatch.setattr(client_mod, "_require_requests", fake_require_requests)

    with pytest.raises(
        RuntimeError, match="Anchoring features require the 'requests' package"
    ):
        client_mod.request_tsa(
            tsa_url="https://example.invalid",
            tsq_bytes=b"dummy",
            timeout_s=0.1,
        )
