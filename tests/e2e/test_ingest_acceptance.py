"""
Frame verification acceptance tests.

Tests that the frame_verifier correctly accepts valid frames and maintains
replay window state across invocations.
"""

from __future__ import annotations

import json


def test_accept_increasing_fc(temp_dirs, frame_verifier, write_frames):
    """Accept frames with increasing frame counter values."""
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-001", 5, temp_dirs["frames"], None, temp_dirs["device_table"])

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


def test_reject_duplicate_and_out_of_window(
    temp_dirs, frame_verifier, write_frames, append_frame_json
):
    """Reject duplicate frames and frames outside the replay window."""
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames(
        "pod-002", 3, temp_dirs["frames"], None, temp_dirs["device_table"]
    )  # fc: 0,1,2

    # Append a duplicate of the last frame and an out-of-window jump
    lines = temp_dirs["frames"].read_text(encoding="utf-8").strip().splitlines()
    if lines:
        # duplicate last frame (fc=2)
        append_frame_json(temp_dirs["frames"], json.loads(lines[-1]))
        # craft a jump frame by modifying fc in JSON to be +100
        f = json.loads(lines[-1])
        f["hdr"]["fc"] = f["hdr"]["fc"] + 100
        append_frame_json(temp_dirs["frames"], f)

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
