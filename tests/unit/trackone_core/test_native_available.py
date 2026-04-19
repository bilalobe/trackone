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


def test_sensorthings_native_smoke() -> None:
    try:
        import trackone_core._native as native
    except ImportError:
        if _require_native():
            raise
        pytest.skip("native extension not available")

    sensorthings = getattr(native, "sensorthings", None)
    if sensorthings is None:
        if _require_native():
            raise AssertionError("native sensorthings submodule unavailable")
        pytest.skip("native sensorthings submodule unavailable")

    thing_id = sensorthings.entity_id("thing", "pod-003")
    projection = sensorthings.project_observation(
        {
            "pod_id": "pod-003",
            "site_id": "an-001",
            "sensor_key": "shtc3-ambient",
            "observed_property_key": "temperature_air",
            "stream_key": "raw",
            "phenomenon_time_start_rfc3339_utc": "2026-03-06T00:05:01Z",
            "phenomenon_time_end_rfc3339_utc": "2026-03-06T00:05:01Z",
            "result_time_rfc3339_utc": "2026-03-06T00:05:01Z",
            "result": 23.5,
        }
    )

    assert isinstance(thing_id, str)
    assert thing_id.startswith("trackone:thing:")
    assert projection["thing"]["id"] == thing_id
    assert projection["datastream"]["stream_key"] == "raw"
    assert projection["observation"]["result"] == 23.5


def test_crypto_validate_and_decrypt_framed_smoke() -> None:
    try:
        import trackone_core.crypto as crypto
    except ImportError:
        if _require_native():
            raise
        pytest.skip("trackone_core.crypto not importable")

    device_entry = {
        "salt8": "0dPrkVqyrzw=",
        "ck_up": "2QmXC8Xl4WRwpgiVg53I8ymATIrlN8AM1DDinl/Z2VU=",
    }
    frame = crypto.emit_rust_postcard_framed_fixture(
        dev_id=3,
        fc=0,
        device_entry=device_entry,
        msg_type=1,
        flags=0,
        pod_time=1_776_048_000,
    )
    payload, reason = crypto.validate_and_decrypt_framed(frame, device_entry)

    assert reason is None
    assert isinstance(payload, dict)
    assert payload["Env"]["sample_type"] == "AmbientAirTemperature"
    assert payload["Env"]["value"] == 20.0
    assert payload["Env"]["phenomenon_time_start"] == 1_776_048_000


def test_crypto_admit_framed_fact_smoke() -> None:
    try:
        import trackone_core.crypto as crypto
    except ImportError:
        if _require_native():
            raise
        pytest.skip("trackone_core.crypto not importable")

    device_entry = {
        "salt8": "0dPrkVqyrzw=",
        "ck_up": "2QmXC8Xl4WRwpgiVg53I8ymATIrlN8AM1DDinl/Z2VU=",
    }
    frame = crypto.emit_rust_postcard_framed_fixture(
        dev_id=3,
        fc=0,
        device_entry=device_entry,
        msg_type=1,
        flags=0,
        pod_time=1_776_048_000,
    )
    state = crypto.ReplayWindowState(window_size=64)

    fact, reason, source = crypto.admit_framed_fact(
        frame,
        device_entry,
        state,
        ingest_time=1_776_048_000,
        ingest_time_rfc3339_utc="2026-04-13T00:00:00Z",
    )

    assert reason is None
    assert source is None
    assert isinstance(fact, dict)
    assert fact["pod_id"] == "0000000000000003"
    assert fact["fc"] == 0
    assert fact["kind"] == "Env"
    assert fact["payload"]["Env"]["sample_type"] == "AmbientAirTemperature"
    assert fact["payload"]["Env"]["value"] == 20.0
    assert state.highest_fc_seen == 0
