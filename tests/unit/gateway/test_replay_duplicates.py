#!/usr/bin/env python3
"""
Tests for replay duplicate detection across restarts (moved from test_replay_edges.py)
"""
from __future__ import annotations


class TestReplayDuplicates:
    def test_duplicate_fc_rejected_across_restart(
        self, temp_dirs, write_device_table, frame_verifier, write_frames
    ):
        """Duplicate frame counter should be rejected even after verifier restart."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-102", 3, temp_dirs["frames"], temp_dirs["device_table"])

        args = [
            "--in",
            str(temp_dirs["frames"]),
            "--out-facts",
            str(temp_dirs["facts"]),
            "--device-table",
            str(temp_dirs["device_table"]),
            "--window",
            "64",
        ]
        # First run
        assert frame_verifier.process(args) == 0
        assert len(list(temp_dirs["facts"].glob("*.json"))) == 3

        # Append duplicate of fc=1
        lines = temp_dirs["frames"].read_text().splitlines()
        # rewrite frames file with duplicate appended
        temp_dirs["frames"].write_text("\n".join(lines) + "\n" + lines[1] + "\n")

        # Clear facts
        import shutil

        shutil.rmtree(temp_dirs["facts"])
        temp_dirs["facts"].mkdir()

        # Second run (simulates restart with persisted device_table)
        assert frame_verifier.process(args) == 0
        # Should still only accept 3 (duplicate rejected)
        assert len(list(temp_dirs["facts"].glob("*.json"))) == 3
