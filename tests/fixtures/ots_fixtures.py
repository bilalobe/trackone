#!/usr/bin/env python3
"""
OTS-specific test fixtures.

Provides fixtures for testing OTS stamping and verification behavior,
including environment control for stationary stub vs real client modes.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture
def disable_stationary_stub():
    """Temporarily disable stationary stub mode for tests that need real ots client behavior.

    Use this fixture when testing the actual subprocess.run code paths with mocked
    subprocess calls, rather than the stationary stub short-circuit.

    Example:
        def test_real_ots_behavior(disable_stationary_stub, ots_anchor):
            with patch("subprocess.run", ...):
                ots_anchor.ots_stamp(...)
    """
    old_val = os.environ.get("OTS_STATIONARY_STUB")
    os.environ["OTS_STATIONARY_STUB"] = "0"
    yield
    if old_val is None:
        os.environ.pop("OTS_STATIONARY_STUB", None)
    else:
        os.environ["OTS_STATIONARY_STUB"] = old_val


@pytest.fixture(scope="module")
def disable_stationary_stub_module():
    """Module-scoped version of disable_stationary_stub.

    Use this when you need to disable stationary stub mode for an entire test module.
    """
    old_val = os.environ.get("OTS_STATIONARY_STUB")
    os.environ["OTS_STATIONARY_STUB"] = "0"
    yield
    if old_val is None:
        os.environ.pop("OTS_STATIONARY_STUB", None)
    else:
        os.environ["OTS_STATIONARY_STUB"] = old_val


@pytest.fixture
def enable_stationary_stub():
    """Temporarily enable stationary stub mode for tests.

    Use this to override the default and force stationary stub behavior.
    """
    old_val = os.environ.get("OTS_STATIONARY_STUB")
    os.environ["OTS_STATIONARY_STUB"] = "1"
    yield
    if old_val is None:
        os.environ.pop("OTS_STATIONARY_STUB", None)
    else:
        os.environ["OTS_STATIONARY_STUB"] = old_val


@pytest.fixture(scope="module")
def enable_stationary_stub_module():
    """Module-scoped version of enable_stationary_stub."""
    old_val = os.environ.get("OTS_STATIONARY_STUB")
    os.environ["OTS_STATIONARY_STUB"] = "1"
    yield
    if old_val is None:
        os.environ.pop("OTS_STATIONARY_STUB", None)
    else:
        os.environ["OTS_STATIONARY_STUB"] = old_val


@pytest.fixture
def ots_calendars():
    """Set custom OTS calendar URLs for tests.

    Returns a callable that sets OTS_CALENDARS env var.

    Example:
        def test_custom_calendar(ots_calendars):
            ots_calendars("http://localhost:8468")
            # ... test code
    """
    old_val = os.environ.get("OTS_CALENDARS")

    def _set(calendars: str):
        os.environ["OTS_CALENDARS"] = calendars

    yield _set

    if old_val is None:
        os.environ.pop("OTS_CALENDARS", None)
    else:
        os.environ["OTS_CALENDARS"] = old_val
