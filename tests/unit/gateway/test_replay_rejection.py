#!/usr/bin/env python3
"""
Tests for replay window rejection cases (moved from test_replay_edges.py)
"""

from __future__ import annotations

import json


class TestReplayWindowRejection:
    def test_reject_beyond_forward_window(
        self, temp_dirs, write_device_table, frame_verifier, write_frames
    ):
        """Frame at highest_fc + window_size + 1 should be rejected."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)
        write_frames("pod-101", 1, temp_dirs["frames"], temp_dirs["device_table"])

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
        assert frame_verifier.process(args) == 0
        assert len(list(temp_dirs["facts"].glob("*.json"))) == 1

        # Reset highest to 0 and generate fc=0..65 in a single run; take last (fc=65)
        dt = json.loads(temp_dirs["device_table"].read_text())
        dt["101"]["highest_fc_seen"] = 0
        write_device_table(temp_dirs["device_table"], dt)

        frames65 = temp_dirs["root"] / "frames65.ndjson"
        write_frames("pod-101", 66, frames65, None, temp_dirs["device_table"])

        lines = frames65.read_text().strip().splitlines()
        assert len(lines) == 66
        last_frame = json.loads(lines[-1])
        assert last_frame["hdr"]["fc"] == 65

        # Reset and test just fc=65 against highest=0
        dt = json.loads(temp_dirs["device_table"].read_text())
        dt["101"]["highest_fc_seen"] = 0
        write_device_table(temp_dirs["device_table"], dt)

        single65 = temp_dirs["root"] / "single65.ndjson"
        single65.write_text(lines[-1])

        facts_test = temp_dirs["root"] / "facts_test"
        args_test = [
            "--in",
            str(single65),
            "--out-facts",
            str(facts_test),
            "--device-table",
            str(temp_dirs["device_table"]),
            "--window",
            "64",
        ]
        assert frame_verifier.process(args_test) == 0
        assert len(list(facts_test.glob("*.json"))) == 0  # fc=65 rejected
