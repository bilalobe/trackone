#!/usr/bin/env python3
"""
Nonce construction tests for pod_sim.build_nonce
"""
from __future__ import annotations


class TestNonceConstruction:
    """Test 24-byte nonce construction (salt8 || fc64 || rand8)."""

    def test_build_nonce_length(self, pod_sim):
        salt = b"\x01" * 8
        fc = 42
        result = pod_sim.build_nonce(salt, fc)
        assert len(result) == 24

    def test_build_nonce_includes_salt(self, pod_sim):
        salt = b"\xaa" * 8
        result = pod_sim.build_nonce(salt, 0)
        assert result[:8] == salt

    def test_build_nonce_different_fc_differs(self, pod_sim):
        salt = b"\x01" * 8
        n1 = pod_sim.build_nonce(salt, 1)
        n2 = pod_sim.build_nonce(salt, 2)
        assert n1[:8] == n2[:8]
        assert n1[8:16] != n2[8:16]

    def test_build_nonce_randomness_tail(self, pod_sim):
        salt = b"\x01" * 8
        fc = 7
        n1 = pod_sim.build_nonce(salt, fc)
        n2 = pod_sim.build_nonce(salt, fc)
        # First 16 bytes (salt+fc) must match
        assert n1[:16] == n2[:16]
        # Tail is random; we don't assert inequality to avoid flakiness
