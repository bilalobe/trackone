# tests/unit/trackone_core/conftest.py
#!/usr/bin/env python3
"""Shared fixtures for trackone_core unit tests."""

from __future__ import annotations

import sys

import pytest


def _clear_trackone_core_modules() -> None:
    for key in list(sys.modules):
        if key == "trackone_core" or key.startswith("trackone_core."):
            sys.modules.pop(key, None)


@pytest.fixture(autouse=True)
def _isolate_trackone_core_import_state() -> None:
    """Ensure tests don't leak mocked/real trackone_core modules across cases."""
    _clear_trackone_core_modules()
    yield
    _clear_trackone_core_modules()
