#!/usr/bin/env python3
"""
Tests for framed telemetry ingest: pod_sim --framed -> frame_verifier -> merkle_batcher -> ots_anchor -> verify_cli
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
    spec.loader.exec_module(mod)  # type: ignore
    return mod


GW_DIR = Path(__file__).parent.parent / "gateway"
frame_verifier = load_module("frame_verifier", GW_DIR / "frame_verifier.py")
merkle_batcher = load_module("merkle_batcher", GW_DIR / "merkle_batcher.py")
verify_cli = load_module("verify_cli", GW_DIR / "verify_cli.py")


def write_frames(device_id: str, count: int, out_path: Path, facts_out: Path | None = None):
    """Use pod_sim to write framed NDJSON to out_path."""
    import subprocess

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
    ]
    if facts_out:
        cmd += ["--facts-out", str(facts_out)]
    subprocess.run(cmd, check=True)


@pytest.fixture
def temp_dirs(tmp_path):
    root = tmp_path / "site_demo"
    frames = root / "frames.ndjson"
    facts = root / "facts"
    device_table = root / "device_table.json"
    out_dir = root
    return {
        "root": root,
        "frames": frames,
        "facts": facts,
        "device_table": device_table,
        "out_dir": out_dir,
    }


def test_accept_increasing_fc(temp_dirs):
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-001", 5, temp_dirs["frames"], None)

    # Verify frames
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

    # Expect 5 fact files
    facts = sorted(temp_dirs["facts"].glob("*.json"))
    assert len(facts) == 5


def test_reject_duplicate_and_out_of_window(temp_dirs):
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-002", 3, temp_dirs["frames"], None)  # fc: 0,1,2

    # Append a duplicate of the last frame and an out-of-window jump
    lines = temp_dirs["frames"].read_text(encoding="utf-8").strip().splitlines()
    if lines:
        with temp_dirs["frames"].open("a", encoding="utf-8") as fh:
            # duplicate last frame (fc=2)
            fh.write(lines[-1] + "\n")
            # craft a jump frame by modifying fc in JSON to be +100
            f = json.loads(lines[-1])
            f["hdr"]["fc"] = f["hdr"]["fc"] + 100
            fh.write(json.dumps(f) + "\n")

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

    # We had 3 unique in-window frames; expect exactly 3 accepted
    facts = sorted(temp_dirs["facts"].glob("*.json"))
    assert len(facts) == 3


def test_end_to_end_pipeline(temp_dirs):
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-003", 7, temp_dirs["frames"], None)

    # 1) Verify frames to facts
    fv_args = [
        "--in",
        str(temp_dirs["frames"]),
        "--out-facts",
        str(temp_dirs["facts"]),
        "--device-table",
        str(temp_dirs["device_table"]),
    ]
    assert frame_verifier.process(fv_args) == 0

    # 2) Batch facts
    day = "2025-10-07"
    batch_args = [
        "--facts",
        str(temp_dirs["facts"]),
        "--out",
        str(temp_dirs["out_dir"]),
        "--site",
        "an-001",
        "--date",
        day,
        "--validate-schemas",
    ]
    assert merkle_batcher.main(batch_args) == 0

    # 3) Write OTS placeholder and verify
    day_bin = temp_dirs["out_dir"] / "day" / f"{day}.bin"
    ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
    ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")

    v_args = ["--root", str(temp_dirs["out_dir"]), "--facts", str(temp_dirs["facts"])]
    assert verify_cli.main(v_args) == 0
