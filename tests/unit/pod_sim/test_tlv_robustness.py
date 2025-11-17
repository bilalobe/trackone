#!/usr/bin/env python3
"""
TLV robustness tests (moved from test_tlv_properties.py)
"""
from __future__ import annotations

import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st


class TestTLVRobustness:
    @given(tlv_data=st.binary(min_size=0, max_size=200))
    def test_decoder_handles_arbitrary_input(self, tlv_data, frame_verifier):
        """Decoder should never crash on arbitrary TLV input."""
        try:
            result = frame_verifier.decode_tlv(tlv_data)
            assert isinstance(result, dict)
        except Exception as e:
            pytest.fail(f"Decoder crashed on input {tlv_data.hex()}: {e}")

    def test_unknown_tags_ignored(self, frame_verifier):
        """Unknown TLV tags should be silently ignored."""
        # Tag 0xFF (unknown), length 2, value 0xABCD
        unknown = bytes([0xFF, 0x02, 0xAB, 0xCD])
        # Tag 0x01 (counter), length 4, value 42
        counter = bytes([0x01, 0x04]) + struct.pack(">I", 42)

        decoded = frame_verifier.decode_tlv(unknown + counter)
        assert decoded.get("counter") == 42
        assert len(decoded) == 1  # unknown tag ignored

    def test_truncated_tlv_handled(self, frame_verifier):
        """Truncated TLV should be handled gracefully."""
        # Tag 0x01, length 4, but only 2 bytes of value
        truncated = bytes([0x01, 0x04, 0x00, 0x01])
        decoded = frame_verifier.decode_tlv(truncated)
        # Should return empty or partial dict without crash
        assert isinstance(decoded, dict)

    def test_zero_length_tlv(self, frame_verifier):
        """Zero-length TLV should be handled."""
        zero_len = bytes([0x01, 0x00])
        decoded = frame_verifier.decode_tlv(zero_len)
        assert isinstance(decoded, dict)
