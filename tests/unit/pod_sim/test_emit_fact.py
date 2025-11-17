#!/usr/bin/env python3
"""
Tests for fact emission from pod_sim.emit_fact
"""
from __future__ import annotations


class TestEmitFact:
    """Test fact generation."""

    def test_emit_fact_structure(self, pod_sim):
        fact = pod_sim.emit_fact("test-pod", 1)
        assert {"device_id", "timestamp", "nonce", "payload"}.issubset(fact)

    def test_emit_fact_device_id(self, pod_sim):
        device_id = "pod-123"
        fact = pod_sim.emit_fact(device_id, 1)
        assert fact["device_id"] == device_id

    def test_emit_fact_nonce_format(self, pod_sim):
        fact = pod_sim.emit_fact("pod-001", 42)
        assert len(fact["nonce"]) == 16
        assert all(c in "0123456789abcdef" for c in fact["nonce"])
        assert fact["nonce"] == f"{42:016x}"

    def test_emit_fact_payload_has_expected_fields(self, pod_sim):
        fact = pod_sim.emit_fact("pod-001", 10)
        payload = fact["payload"]
        assert payload["counter"] == 10
        assert "bioimpedance" in payload
        assert "temp_c" in payload

    def test_emit_fact_payload_values_in_range(self, pod_sim):
        for i in range(5):
            payload = pod_sim.emit_fact("pod-001", i)["payload"]
            assert 50.0 <= payload["bioimpedance"] <= 120.0
            assert 20.0 <= payload["temp_c"] <= 40.0

    def test_emit_fact_timestamp_format(self, pod_sim):
        fact = pod_sim.emit_fact("pod-001", 1)
        timestamp = fact["timestamp"]
        assert "T" in timestamp
        # Allow both Z and +00:00 forms
        assert timestamp.endswith("Z") or "+00:00" in timestamp
