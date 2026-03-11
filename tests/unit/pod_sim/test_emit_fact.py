#!/usr/bin/env python3
"""
Tests for fact emission from pod_sim.emit_fact
"""
from __future__ import annotations


class TestEmitFact:
    """Test fact generation."""

    def test_emit_fact_structure(self, pod_sim):
        fact = pod_sim.emit_fact("test-pod", 1)
        assert {
            "pod_id",
            "fc",
            "ingest_time",
            "ingest_time_rfc3339_utc",
            "pod_time",
            "kind",
            "payload",
        }.issubset(fact)

    def test_emit_fact_pod_id_and_fc(self, pod_sim):
        fact = pod_sim.emit_fact("pod-001", 42)
        assert fact["pod_id"] == "0000000000000001"
        assert fact["fc"] == 42

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
        timestamp = fact["ingest_time_rfc3339_utc"]
        assert "T" in timestamp
        # Allow both Z and +00:00 forms
        assert timestamp.endswith("Z") or "+00:00" in timestamp
