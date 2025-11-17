#!/usr/bin/env python3
"""
Tests for replay window acceptance cases (moved from test_replay_edges.py)
"""
from __future__ import annotations

import json


class TestReplayWindowAcceptance:
    def test_accept_within_forward_window(
        self, temp_dirs, write_device_table, frame_verifier, write_frames
    ):
        """Frame at exactly highest_fc + window_size should be accepted."""
        temp_dirs["root"].mkdir(parents=True, exist_ok=True)

        # Generate fc=0 and verify to persist device state with highest=0
        write_frames("pod-100", 1, temp_dirs["frames"], temp_dirs["device_table"])

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

        # Produce frames with fc=0..64 in a single run and pick the last (fc=64)
        import subprocess
        import sys

        frames64 = temp_dirs["root"] / "frames64.ndjson"
        subprocess.run(
            [
                sys.executable,
                "scripts/pod_sim/pod_sim.py",
                "--device-id",
                "pod-100",
                "--count",
                "65",  # fc 0..64
                "--framed",
                "--out",
                str(frames64),
                "--device-table",
                str(temp_dirs["device_table"]),
            ],
            check=True,
            capture_output=True,
        )

        # Last frame should be fc=64
        lines = frames64.read_text().strip().splitlines()
        assert len(lines) == 65
        last_frame = json.loads(lines[-1])
        assert last_frame["hdr"]["fc"] == 64

        # Reset device_table highest to 0 to test boundary acceptance of fc=64
        dt = json.loads(temp_dirs["device_table"].read_text())
        dt["100"]["highest_fc_seen"] = 0
        write_device_table(temp_dirs["device_table"], dt)

        single_frame = temp_dirs["root"] / "single64.ndjson"
        single_frame.write_text(lines[-1])

        facts_new = temp_dirs["root"] / "facts_new"
        args_new = [
            "--in",
            str(single_frame),
            "--out-facts",
            str(facts_new),
            "--device-table",
            str(temp_dirs["device_table"]),
            "--window",
            "64",
        ]
        assert frame_verifier.process(args_new) == 0
        assert len(list(facts_new.glob("*.json"))) == 1  # fc=64 accepted
