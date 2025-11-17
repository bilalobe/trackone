#!/usr/bin/env python3
"""
TLV encoding tests (moved from test_pod_sim.TestTLVEncoding)
"""
from __future__ import annotations


class TestTLVEncoding:
    """Test TLV encoding."""

    def test_encode_tlv_structure(self, pod_sim):
        payload = {"counter": 1, "bioimpedance": 50.5, "temp_c": 25.0}
        result = pod_sim.encode_tlv(payload)
        assert isinstance(result, bytes)
        assert len(result) >= 14

    def test_encode_tlv_deterministic(self, pod_sim):
        payload = {"counter": 10, "bioimpedance": 60.0, "temp_c": 23.0}
        # Deterministic: same input -> same output
        assert pod_sim.encode_tlv(payload) == pod_sim.encode_tlv(payload)

    def test_encode_tlv_different_payloads_differ(self, pod_sim):
        p1 = {"counter": 1, "bioimpedance": 50.0, "temp_c": 20.0}
        p2 = {"counter": 2, "bioimpedance": 50.0, "temp_c": 20.0}
        assert pod_sim.encode_tlv(p1) != pod_sim.encode_tlv(p2)
