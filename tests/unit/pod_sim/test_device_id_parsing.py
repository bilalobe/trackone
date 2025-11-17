#!/usr/bin/env python3
"""
Tests for device ID parsing in pod_sim
"""
from __future__ import annotations

import pytest


class TestDeviceIdParsing:
    """Test device ID parsing to u16."""

    def test_parse_dev_id_u16_with_number(self, pod_sim):
        assert pod_sim.parse_dev_id_u16("pod-123") == 123

    def test_parse_dev_id_u16_single_digit(self, pod_sim):
        assert pod_sim.parse_dev_id_u16("pod-5") == 5

    def test_parse_dev_id_u16_no_number(self, pod_sim):
        assert pod_sim.parse_dev_id_u16("pod") == 1

    def test_parse_dev_id_u16_large_number(self, pod_sim):
        val = pod_sim.parse_dev_id_u16("pod-999999")
        assert isinstance(val, int)
        assert val <= 65535

    def test_parse_dev_id_u16_zero(self, pod_sim):
        assert pod_sim.parse_dev_id_u16("pod-0") == 0

    @pytest.mark.parametrize(
        "device_id,expected",
        [("pod-001", 1), ("pod-042", 42), ("device-100", 100), ("sensor-9999", 9999)],
    )
    def test_parse_dev_id_u16_parametrized(self, pod_sim, device_id, expected):
        assert pod_sim.parse_dev_id_u16(device_id) == expected
