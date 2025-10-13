#!/usr/bin/env python3
"""
Property-based tests for TLV encoding/decoding using Hypothesis.
"""
from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

GW_DIR = Path(__file__).parent.parent / "gateway"
sys.path.insert(0, str(GW_DIR))

# Load frame_verifier for decode_tlv
spec = importlib.util.spec_from_file_location(
    "frame_verifier", str(GW_DIR / "frame_verifier.py")
)
assert spec and spec.loader
frame_verifier = importlib.util.module_from_spec(spec)
sys.modules["frame_verifier"] = frame_verifier
spec.loader.exec_module(frame_verifier)  # type: ignore

# Load pod_sim for encode_tlv
pod_spec = importlib.util.spec_from_file_location(
    "pod_sim", Path(__file__).parent.parent / "pod_sim" / "pod_sim.py"
)
assert pod_spec and pod_spec.loader
pod_sim = importlib.util.module_from_spec(pod_spec)
sys.modules["pod_sim"] = pod_sim
pod_spec.loader.exec_module(pod_sim)  # type: ignore


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
    def test_encode_decode_round_trip(self, counter, bioimpedance, temp_c):
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


class TestTLVRobustness:
    @given(tlv_data=st.binary(min_size=0, max_size=200))
    def test_decoder_handles_arbitrary_input(self, tlv_data):
        """Decoder should never crash on arbitrary TLV input."""
        try:
            result = frame_verifier.decode_tlv(tlv_data)
            assert isinstance(result, dict)
        except Exception as e:
            pytest.fail(f"Decoder crashed on input {tlv_data.hex()}: {e}")

    def test_unknown_tags_ignored(self):
        """Unknown TLV tags should be silently ignored."""
        # Tag 0xFF (unknown), length 2, value 0xABCD
        unknown = bytes([0xFF, 0x02, 0xAB, 0xCD])
        # Tag 0x01 (counter), length 4, value 42
        counter = bytes([0x01, 0x04]) + struct.pack(">I", 42)

        decoded = frame_verifier.decode_tlv(unknown + counter)
        assert decoded.get("counter") == 42
        assert len(decoded) == 1  # unknown tag ignored

    def test_truncated_tlv_handled(self):
        """Truncated TLV should be handled gracefully."""
        # Tag 0x01, length 4, but only 2 bytes of value
        truncated = bytes([0x01, 0x04, 0x00, 0x01])
        decoded = frame_verifier.decode_tlv(truncated)
        # Should return empty or partial dict without crash
        assert isinstance(decoded, dict)

    def test_zero_length_tlv(self):
        """Zero-length TLV should be handled."""
        zero_len = bytes([0x01, 0x00])
        decoded = frame_verifier.decode_tlv(zero_len)
        assert isinstance(decoded, dict)
