#!/usr/bin/env python3
"""Tests that require the native extension to be importable."""

from __future__ import annotations

import os

import pytest


def _require_native() -> bool:
    value = os.environ.get("TRACKONE_REQUIRE_NATIVE", "").lower()
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    return False


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


def test_crypto_validate_and_decrypt_framed_smoke() -> None:
    try:
        import trackone_core.crypto as crypto
    except ImportError:
        if _require_native():
            raise
        pytest.skip("trackone_core.crypto not importable")

    frame = {
        "hdr": {"dev_id": 3, "msg_type": 1, "fc": 0, "flags": 0},
        "nonce": "0dPrkVqyrzwAAAAAAAAAAN8GlwmTN0eL",
        "ct": "23gboJSYJiwhuJntomk=",
        "tag": "e1a45uix1rwmceIwbu4HPQ==",
    }
    device_entry = {
        "salt8": "0dPrkVqyrzw=",
        "ck_up": "2QmXC8Xl4WRwpgiVg53I8ymATIrlN8AM1DDinl/Z2VU=",
    }
    payload, reason = crypto.validate_and_decrypt_framed(frame, device_entry)

    assert reason is None
    assert isinstance(payload, dict)
    assert payload["counter"] == 0
    assert payload["bioimpedance"] == 98.61
    assert payload["temp_c"] == 38.72
