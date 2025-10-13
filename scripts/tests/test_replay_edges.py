#!/usr/bin/env python3
"""
Test replay window edge cases and persistence across restarts.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore
    return mod


GW_DIR = Path(__file__).parent.parent / "gateway"
frame_verifier = load_module("frame_verifier", GW_DIR / "frame_verifier.py")


@pytest.fixture
def temp_dirs(tmp_path):
    root = tmp_path / "replay_test"
    frames = root / "frames.ndjson"
    facts = root / "facts"
    device_table = root / "device_table.json"
    return {
        "root": root,
        "frames": frames,
        "facts": facts,
        "device_table": device_table,
    }


def write_frames(device_id: str, count: int, out_path: Path, device_table: Path):
    import subprocess

    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "scripts/pod_sim/pod_sim.py",
        "--device-id",
        device_id,
        "--count",
        str(count),
        "--framed",
        "--out",
        str(out_path),
        "--device-table",
        str(device_table),
    ]
    subprocess.run(cmd, check=True)


class TestReplayWindowEdges:
    def test_accept_within_forward_window(self, temp_dirs):
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
        temp_dirs["device_table"].write_text(json.dumps(dt, indent=2))

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

    def test_reject_beyond_forward_window(self, temp_dirs):
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
        temp_dirs["device_table"].write_text(json.dumps(dt, indent=2))

        import subprocess

        frames65 = temp_dirs["root"] / "frames65.ndjson"
        subprocess.run(
            [
                sys.executable,
                "scripts/pod_sim/pod_sim.py",
                "--device-id",
                "pod-101",
                "--count",
                "66",  # fc 0..65
                "--framed",
                "--out",
                str(frames65),
                "--device-table",
                str(temp_dirs["device_table"]),
            ],
            check=True,
            capture_output=True,
        )

        lines = frames65.read_text().strip().splitlines()
        assert len(lines) == 66
        last_frame = json.loads(lines[-1])
        assert last_frame["hdr"]["fc"] == 65

        # Reset and test just fc=65 against highest=0
        dt = json.loads(temp_dirs["device_table"].read_text())
        dt["101"]["highest_fc_seen"] = 0
        temp_dirs["device_table"].write_text(json.dumps(dt, indent=2))

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

    def test_duplicate_fc_rejected_across_restart(self, temp_dirs):
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
        temp_dirs["frames"].write_text("\n".join(lines) + "\n" + lines[1] + "\n")

        # Clear facts
        import shutil

        shutil.rmtree(temp_dirs["facts"])
        temp_dirs["facts"].mkdir()

        # Second run (simulates restart with persisted device_table)
        assert frame_verifier.process(args) == 0
        # Should still only accept 3 (duplicate rejected)
        assert len(list(temp_dirs["facts"].glob("*.json"))) == 3
