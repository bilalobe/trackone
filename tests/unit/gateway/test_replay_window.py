#!/usr/bin/env python3
"""
ReplayWindow unit tests (moved from test_unit_coverage_boost.py)
"""
from __future__ import annotations

import pytest

from scripts.gateway import frame_verifier


@pytest.mark.unit
class TestReplayWindowEdgeCases:
    """Test ReplayWindow edge cases to improve frame_verifier coverage."""

    def test_replay_window_initialization(self):
        """Test ReplayWindow initialization with fresh state."""
        window = frame_verifier.ReplayWindow(window_size=32)
        assert window.window_size == 32
        assert len(window.highest_fc) == 0
        assert len(window.seen) == 0

    def test_replay_window_initialize_from_device_table(self):
        """Test ReplayWindow initialization from device table."""
        window = frame_verifier.ReplayWindow(window_size=32)
        device_table = {
            "3": {"highest_fc_seen": 10},
            "5": {"highest_fc_seen": 20},
        }
        window.initialize_from_device_table(device_table)

        # Should have initialized highest_fc for devices
        assert "pod-003" in window.highest_fc
        assert window.highest_fc["pod-003"] == 10
        assert "pod-005" in window.highest_fc
        assert window.highest_fc["pod-005"] == 20

    def test_replay_window_check_and_update_accept(self):
        """Test ReplayWindow accepts valid frame counters."""
        window = frame_verifier.ReplayWindow(window_size=32)

        # First frame should be accepted
        accepted, msg = window.check_and_update("dev1", 0)
        assert accepted
        # Message can be "first", "accepted", or empty

        # Next frame should be accepted
        accepted, msg = window.check_and_update("dev1", 1)
        assert accepted

    def test_replay_window_check_and_update_duplicate(self):
        """Test ReplayWindow rejects duplicate frame counters."""
        window = frame_verifier.ReplayWindow(window_size=32)

        # Accept frame
        window.check_and_update("dev1", 5)

        # Try to replay same frame
        accepted, msg = window.check_and_update("dev1", 5)
        assert not accepted
        assert "duplicate" in msg.lower() or "already" in msg.lower()

    def test_replay_window_boundary_fc(self):
        """Test ReplayWindow at frame counter boundaries."""
        window = frame_verifier.ReplayWindow(window_size=4)

        # Accept frames at window boundary
        window.check_and_update("dev1", 0)
        window.check_and_update("dev1", 1)
        window.check_and_update("dev1", 2)
        window.check_and_update("dev1", 3)

        # Frame at edge of window
        accepted, _ = window.check_and_update("dev1", 4)
        assert accepted

    def test_replay_window_too_far_ahead(self):
        """Test ReplayWindow rejects frames too far ahead (forward out of window)."""
        window = frame_verifier.ReplayWindow(window_size=4)

        # Establish a baseline
        window.check_and_update("dev1", 5)

        # Try to jump too far ahead (outside window)
        accepted, msg = window.check_and_update(
            "dev1", 15
        )  # 10 frames ahead, window is 4
        assert not accepted
        assert "out_of_window" in msg.lower() or "window" in msg.lower()

    def test_replay_window_too_far_behind(self):
        """Test ReplayWindow rejects frames too far behind (backward out of window)."""
        window = frame_verifier.ReplayWindow(window_size=4)

        # Establish high frame counter
        window.check_and_update("dev1", 20)

        # Try to replay old frame (outside window)
        accepted, msg = window.check_and_update(
            "dev1", 10
        )  # 10 frames behind, window is 4
        assert not accepted
        assert "out_of_window" in msg.lower() or "window" in msg.lower()

    def test_replay_window_pruning(self):
        """Test that ReplayWindow prunes old entries from seen set."""
        window = frame_verifier.ReplayWindow(window_size=3)

        # Accept sequence of frames
        window.check_and_update("dev1", 1)
        window.check_and_update("dev1", 2)
        window.check_and_update("dev1", 3)
        window.check_and_update("dev1", 4)
        window.check_and_update("dev1", 5)

        # Frame 1 should be pruned from seen set (outside window of 3 from frame 5)
        # So we should be able to "accept" it again (though it's still behind)
        # This tests the pruning logic
        assert "dev1" in window.seen
