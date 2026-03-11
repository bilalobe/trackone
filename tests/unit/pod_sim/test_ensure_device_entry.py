#!/usr/bin/env python3
"""
Tests for ensure_device_entry behavior in pod_sim
"""
from __future__ import annotations


class TestEnsureDeviceEntry:
    """Test ensure_device_entry creates and returns device entries."""

    def test_ensure_device_entry_creates_new_entry(self, pod_sim):
        tbl: dict = {}
        entry = pod_sim.ensure_device_entry(tbl, 100, site_id="an-001")
        assert "_meta" in tbl
        assert "master_seed" in tbl["_meta"]
        assert "version" in tbl["_meta"]
        assert "100" in tbl
        assert {"salt8", "ck_up", "highest_fc_seen"}.issubset(tbl["100"])  # type: ignore[index]
        assert entry["deployment"]["deployment_sensor_key"] == "shtc3-ambient"
        assert entry["deployment"]["sensor_keys"]["temperature_air"] == "shtc3-ambient"
        assert (
            entry["deployment"]["sensor_keys"]["bioimpedance_magnitude"]
            == "bioimpedance-pad"
        )
        assert len(entry["provisioning"]["identity_pubkey"]) == 64
        assert len(entry["provisioning"]["firmware_hash"]) == 64
        assert len(entry["provisioning"]["birth_cert_sig"]) == 128
        assert entry["provisioning"]["site_id"] == "an-001"
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
            "100": {
                "salt8": salt_b64,
                "ck_up": key_b64,
                "highest_fc_seen": 5,
                "deployment": {
                    "deployment_sensor_key": "custom-sensor",
                    "sensor_keys": {"temperature_air": "custom-sensor"},
                },
                "provisioning": {
                    "identity_pubkey": "a" * 64,
                    "firmware_version": "v9.9.9",
                    "firmware_hash": "b" * 64,
                    "birth_cert_sig": "c" * 128,
                    "provisioned_at": 123,
                },
            },
        }
        entry = pod_sim.ensure_device_entry(tbl, 100, site_id="an-001")
        assert entry["salt8"] == salt_b64
        assert entry["ck_up"] == key_b64
        assert entry["highest_fc_seen"] == 5
        assert entry["deployment"]["deployment_sensor_key"] == "custom-sensor"
        assert entry["provisioning"]["firmware_version"] == "v9.9.9"

    def test_ensure_device_entry_backfills_missing_metadata(self, pod_sim):
        import base64

        tbl = {
            "_meta": {
                "master_seed": base64.b64encode(b"seed" * 8).decode(),
                "version": "1.0",
            },
            "100": {
                "salt8": base64.b64encode(b"\xaa" * 8).decode(),
                "ck_up": base64.b64encode(b"\xbb" * 32).decode(),
            },
        }

        entry = pod_sim.ensure_device_entry(tbl, 100, site_id="an-001")

        assert "deployment" in entry
        assert "provisioning" in entry
        assert entry["provisioning"]["site_id"] == "an-001"
