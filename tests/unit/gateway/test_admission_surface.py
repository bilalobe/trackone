from __future__ import annotations

import io
import json
from datetime import UTC, datetime

from trackone_core.admission import (
    RejectionRecord,
    admission_state_update,
    apply_admission_state_update,
    audit_day_label,
    emit_rejection,
    hash_rejected_line,
)


class _ReplayState:
    highest_fc_seen = 42


def test_rejection_record_surface_serializes_stable_ndjson() -> None:
    out = io.StringIO()
    record = RejectionRecord(
        device_id="pod-003",
        fc=7,
        reason="duplicate",
        observed_at_utc="2026-04-25T12:00:00+00:00",
        frame_sha256="a" * 64,
        source="replay",
    )

    emit_rejection(out, record)

    assert json.loads(out.getvalue()) == {
        "device_id": "pod-003",
        "fc": 7,
        "frame_sha256": "a" * 64,
        "observed_at_utc": "2026-04-25T12:00:00+00:00",
        "reason": "duplicate",
        "source": "replay",
    }


def test_admission_state_update_applies_replay_state_highest_counter() -> None:
    device_table = {"3": {"highest_fc_seen": 5}}
    observed_at = datetime(2026, 4, 25, 12, 0, tzinfo=UTC)

    update = admission_state_update(
        device_key="3",
        device_table_entry=device_table["3"],
        replay_state=_ReplayState(),
        accepted_fc=7,
        observed_at=observed_at,
        msg_type=1,
        flags=0,
    )
    apply_admission_state_update(device_table, update)

    assert device_table["3"] == {
        "highest_fc_seen": 42,
        "last_seen": "2026-04-25T12:00:00+00:00",
        "msg_type": 1,
        "flags": 0,
    }


def test_hash_and_audit_day_are_stable() -> None:
    assert hash_rejected_line('{"hdr":{"dev_id":3}}\n') == hash_rejected_line(
        '{"hdr":{"dev_id":3}}\r\n'
    )
    assert audit_day_label(datetime(2026, 4, 25, 12, 0, tzinfo=UTC)) == "2026-04-25"
