#!/usr/bin/env python3
"""
Property-based round-trip TLV tests (moved from test_tlv_properties.py)
"""
from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st


class TestTLVRoundTrip:
    @given(
        counter=st.integers(min_value=0, max_value=0xFFFFFFFF),
        bioimpedance=st.floats(
            min_value=0.0, max_value=655.35, allow_nan=False, allow_infinity=False
        ),
        temp_c=st.floats(
            min_value=-327.68, max_value=327.67, allow_nan=False, allow_infinity=False
        ),
    )
    def test_encode_decode_round_trip(
        self, counter, bioimpedance, temp_c, pod_sim, frame_verifier
    ):
        """Encoding and decoding should round-trip for valid payloads."""
        payload = {
            "counter": counter,
            "bioimpedance": round(bioimpedance, 2),
            "temp_c": round(temp_c, 2),
        }

        encoded = pod_sim.encode_tlv(payload)
        decoded = frame_verifier.decode_tlv(encoded)

        # Counter should match exactly
        assert decoded["counter"] == counter
        # Floats should match within precision (scaled by 100, stored as int)
        assert abs(decoded["bioimpedance"] - payload["bioimpedance"]) < 0.02
        assert abs(decoded["temp_c"] - payload["temp_c"]) < 0.02
