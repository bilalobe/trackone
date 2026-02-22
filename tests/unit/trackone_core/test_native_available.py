#!/usr/bin/env python3
"""Tests that require the native extension to be importable."""

from __future__ import annotations

import pytest

from scripts.gateway.config import get_bool_env


def _require_native() -> bool:
    return get_bool_env("TRACKONE_REQUIRE_NATIVE", False)


def test_native_extension_importable() -> None:
    try:
        import trackone_core._native as native  # noqa: F401
    except ImportError:
        if _require_native():
            raise
        pytest.skip("native extension not available")


def test_merkle_smoke() -> None:
    try:
        import trackone_core
    except ImportError:
        if _require_native():
            raise
        pytest.skip("trackone_core not importable")

    try:
        got = trackone_core.merkle.merkle_root_hex([])
    except ImportError:
        if _require_native():
            raise
        pytest.skip("native extension not available")

    assert isinstance(got, str)
    assert len(got) == 64
