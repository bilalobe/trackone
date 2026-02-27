#!/usr/bin/env python3
"""Integration tests for structured rejection audit logging."""

from __future__ import annotations

import json


def _read_rejections(audit_dir):
    paths = sorted(audit_dir.glob("rejections-*.ndjson"))
    assert len(paths) == 1
    lines = [line for line in paths[0].read_text(encoding="utf-8").splitlines() if line]
    return [json.loads(line) for line in lines]


def test_replay_rejection_writes_structured_record(
    temp_dirs, write_frames, frame_verifier
) -> None:
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-021", 1, temp_dirs["frames"], temp_dirs["device_table"])

    args = [
        "--in",
        str(temp_dirs["frames"]),
        "--out-facts",
        str(temp_dirs["facts"]),
        "--device-table",
        str(temp_dirs["device_table"]),
    ]

    assert frame_verifier.process(args) == 0
    assert frame_verifier.process(args) == 0

    records = _read_rejections(temp_dirs["root"] / "audit")
    assert len(records) == 1
    assert records[0]["source"] == "replay"
    assert records[0]["reason"] == "duplicate"
    assert records[0]["device_id"] == "pod-021"
    assert records[0]["fc"] == 0


def test_decrypt_rejection_writes_structured_record(
    temp_dirs, write_frames, write_frame_json, frame_verifier
) -> None:
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-022", 1, temp_dirs["frames"], temp_dirs["device_table"])

    frame = json.loads(temp_dirs["frames"].read_text(encoding="utf-8").strip())
    frame["hdr"]["dev_id"] = 999
    write_frame_json(temp_dirs["frames"], frame)

    args = [
        "--in",
        str(temp_dirs["frames"]),
        "--out-facts",
        str(temp_dirs["facts"]),
        "--device-table",
        str(temp_dirs["device_table"]),
    ]

    assert frame_verifier.process(args) == 0
    assert not list(temp_dirs["facts"].glob("*.json"))

    records = _read_rejections(temp_dirs["root"] / "audit")
    assert len(records) == 1
    assert records[0]["source"] == "decrypt"
    assert records[0]["reason"] == "decrypt_failed"
    assert records[0]["device_id"] == "pod-999"
    assert records[0]["fc"] == 0


def test_multiple_process_runs_append_to_same_daily_audit_log(
    temp_dirs, frame_verifier
) -> None:
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    temp_dirs["frames"].write_text("not valid json\n", encoding="utf-8")

    args = [
        "--in",
        str(temp_dirs["frames"]),
        "--out-facts",
        str(temp_dirs["facts"]),
        "--device-table",
        str(temp_dirs["device_table"]),
    ]

    assert frame_verifier.process(args) == 0
    assert frame_verifier.process(args) == 0

    records = _read_rejections(temp_dirs["root"] / "audit")
    assert len(records) == 2
    assert all(record["reason"] == "invalid_json" for record in records)


def test_merkle_batcher_ignores_sibling_audit_directory(
    temp_dirs, write_frames, frame_verifier, merkle_batcher
) -> None:
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    write_frames("pod-023", 1, temp_dirs["frames"], temp_dirs["device_table"])

    verify_args = [
        "--in",
        str(temp_dirs["frames"]),
        "--out-facts",
        str(temp_dirs["facts"]),
        "--device-table",
        str(temp_dirs["device_table"]),
    ]
    assert frame_verifier.process(verify_args) == 0

    audit_dir = temp_dirs["root"] / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / "rejections-2025-10-07.ndjson").write_text(
        '{"device_id":"pod-023","fc":1,"reason":"duplicate"}\n',
        encoding="utf-8",
    )

    batch_args = [
        "--facts",
        str(temp_dirs["facts"]),
        "--out",
        str(temp_dirs["out_dir"]),
        "--site",
        "test-site",
        "--date",
        "2025-10-07",
    ]
    assert merkle_batcher.main(batch_args) == 0

    block_path = temp_dirs["root"] / "blocks" / "2025-10-07-00.block.json"
    block_header = json.loads(block_path.read_text(encoding="utf-8"))
    fact_leaves = [
        path.read_bytes() for path in sorted(temp_dirs["facts"].glob("*.cbor"))
    ]
    expected_root, _leaf_hashes = merkle_batcher.merkle_root_from_leaves(fact_leaves)

    assert block_header["merkle_root"] == expected_root
