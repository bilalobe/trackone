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


def test_ledger_digest_and_hex_helpers_smoke() -> None:
    try:
        import trackone_core
    except ImportError:
        if _require_native():
            raise
        pytest.skip("trackone_core not importable")

    try:
        digest = trackone_core.ledger.sha256_hex(b"abc")
        normalized = trackone_core.ledger.normalize_hex64("A" * 64)
    except ImportError:
        if _require_native():
            raise
        pytest.skip("native extension not available")

    assert digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert normalized == "a" * 64
