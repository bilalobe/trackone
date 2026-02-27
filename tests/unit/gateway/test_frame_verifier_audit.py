#!/usr/bin/env python3
"""Unit tests for frame_verifier rejection audit logging."""

from __future__ import annotations

import json


def _read_rejections(audit_dir):
    paths = sorted(audit_dir.glob("rejections-*.ndjson"))
    assert len(paths) == 1
    lines = [line for line in paths[0].read_text(encoding="utf-8").splitlines() if line]
    return [json.loads(line) for line in lines]


def test_emit_rejection_serializes_ndjson_record(tmp_path, frame_verifier) -> None:
    audit_path = tmp_path / "rejections.ndjson"
    record = frame_verifier.RejectionRecord(
        device_id="pod-001",
        fc=7,
        reason="duplicate",
        observed_at_utc="2026-02-27T00:00:00+00:00",
        frame_sha256="a" * 64,
        source="replay",
    )

    with audit_path.open("w", encoding="utf-8") as out_fh:
        frame_verifier._emit_rejection(out_fh, record)

    data = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert data == {
        "device_id": "pod-001",
        "fc": 7,
        "frame_sha256": "a" * 64,
        "observed_at_utc": "2026-02-27T00:00:00+00:00",
        "reason": "duplicate",
        "source": "replay",
    }


def test_hash_rejected_line_is_stable(frame_verifier) -> None:
    raw_line = '{"hdr":{"dev_id":1}}\n'

    first = frame_verifier._hash_rejected_line(raw_line)
    second = frame_verifier._hash_rejected_line(raw_line)

    assert first == second
    assert len(first) == 64


def test_process_writes_parse_rejection_record(temp_dirs, frame_verifier) -> None:
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

    records = _read_rejections(temp_dirs["root"] / "audit")
    assert len(records) == 1
    assert records[0]["source"] == "parse"
    assert records[0]["reason"] == "invalid_json"
    assert records[0]["device_id"] == ""
    assert records[0]["fc"] is None
    assert len(records[0]["frame_sha256"]) == 64


def test_process_honors_custom_out_audit(temp_dirs, frame_verifier) -> None:
    temp_dirs["root"].mkdir(parents=True, exist_ok=True)
    temp_dirs["frames"].write_text("not valid json\n", encoding="utf-8")
    custom_audit = temp_dirs["root"] / "custom_audit"

    args = [
        "--in",
        str(temp_dirs["frames"]),
        "--out-facts",
        str(temp_dirs["facts"]),
        "--out-audit",
        str(custom_audit),
        "--device-table",
        str(temp_dirs["device_table"]),
    ]

    assert frame_verifier.process(args) == 0

    assert not (temp_dirs["root"] / "audit").exists()
    records = _read_rejections(custom_audit)
    assert len(records) == 1
    assert records[0]["reason"] == "invalid_json"
