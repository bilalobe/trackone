#!/usr/bin/env python3
"""
Tests for device table load/save and roundtrip in pod_sim
"""
from __future__ import annotations

import json


class TestDeviceTableOperations:
    """Test device table load/save."""

    def test_load_device_table_creates_new(self, tmp_path, pod_sim):
        dt_path = tmp_path / "device_table.json"
        result = pod_sim.load_device_table(dt_path)
        assert isinstance(result, dict)
        assert len(result) == 0
        # Should not create file when loading non-existent path
        assert not dt_path.exists()

    def test_load_device_table_reads_existing(
        self, tmp_path, pod_sim, write_device_table
    ):
        dt_path = tmp_path / "device_table.json"
        existing = {"100": {"highest_fc_seen": 42}}
        write_device_table(dt_path, existing, indent=None)
        assert pod_sim.load_device_table(dt_path) == existing

    def test_save_device_table(self, tmp_path, pod_sim):
        dt_path = tmp_path / "device_table.json"
        data = {
            "100": {
                "salt8": "base64data",
                "ck_up": "base64key",
                "highest_fc_seen": 12,
            }
        }
        pod_sim.save_device_table(dt_path, data)
        assert dt_path.exists()
        assert json.loads(dt_path.read_text(encoding="utf-8")) == data

    def test_device_table_roundtrip(self, tmp_path, pod_sim):
        dt_path = tmp_path / "device_table.json"
        original = {
            "100": {
                "salt8": "xyz",
                "ck_up": "abc",
                "highest_fc_seen": 10,
            }
        }
        pod_sim.save_device_table(dt_path, original)
        loaded = pod_sim.load_device_table(dt_path)
        assert loaded == original
