#!/usr/bin/env python3
"""
Tests for ensure_device_entry behavior in pod_sim
"""
from __future__ import annotations


class TestEnsureDeviceEntry:
    """Test ensure_device_entry creates and returns device entries."""

    def test_ensure_device_entry_creates_new_entry(self, pod_sim):
        tbl: dict = {}
        entry = pod_sim.ensure_device_entry(tbl, 100)
        assert "_meta" in tbl
        assert "master_seed" in tbl["_meta"]
        assert "version" in tbl["_meta"]
        assert "100" in tbl
        assert {"salt8", "ck_up", "highest_fc_seen"}.issubset(tbl["100"])  # type: ignore[index]
        assert isinstance(entry, dict)

    def test_ensure_device_entry_returns_existing(self, pod_sim):
        import base64

        salt_b64 = base64.b64encode(b"\xaa" * 8).decode()
        key_b64 = base64.b64encode(b"\xbb" * 32).decode()
        tbl = {
            "_meta": {
                "master_seed": base64.b64encode(b"seed" * 8).decode(),
                "version": "1.0",
            },
            "100": {"salt8": salt_b64, "ck_up": key_b64, "highest_fc_seen": 5},
        }
        entry = pod_sim.ensure_device_entry(tbl, 100)
        assert entry["salt8"] == salt_b64
        assert entry["ck_up"] == key_b64
        assert entry["highest_fc_seen"] == 5
