"""Gateway admission-state and rejection-audit helper shapes."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, TextIO

REJECTION_SOURCE_PARSE = "parse"
REJECTION_SOURCE_DECRYPT = "decrypt"
REJECTION_SOURCE_REPLAY = "replay"
REJECTION_SOURCE_TAXONOMY = (
    REJECTION_SOURCE_PARSE,
    REJECTION_SOURCE_DECRYPT,
    REJECTION_SOURCE_REPLAY,
)

REJECTION_REASON_TAXONOMY = (
    "line_too_long",
    "invalid_json",
    "not_dict",
    "missing_frame_fields",
    "unexpected_frame_fields",
    "invalid_hdr",
    "invalid_frame_types",
    "missing_hdr_fields",
    "unexpected_hdr_fields",
    "invalid_hdr_types",
    "dev_id_range",
    "msg_type_range",
    "fc_range",
    "flags_range",
    "invalid_ingest_profile",
    "unsupported_flags",
    "unknown_device",
    "missing_salt8",
    "invalid_base64",
    "salt8_length",
    "ck_up_length",
    "nonce_length",
    "tag_length",
    "empty_ciphertext",
    "ciphertext_too_large",
    "nonce_salt_mismatch",
    "nonce_fc_mismatch",
    "decrypt_failed",
    "postcard_pod_id_mismatch",
    "postcard_fc_mismatch",
    "duplicate",
    "out_of_window",
)


@dataclass(slots=True, frozen=True)
class RejectionRecord:
    device_id: str
    fc: int | None
    reason: str
    observed_at_utc: str
    frame_sha256: str
    source: str


@dataclass(slots=True, frozen=True)
class AdmissionStateUpdate:
    device_key: str
    highest_fc_seen: int
    last_seen: str
    msg_type: int
    flags: int


def hash_rejected_line(raw_line: str) -> str:
    """Hash a rejected raw frame line, ignoring only trailing newline bytes."""
    return sha256(raw_line.rstrip("\r\n").encode("utf-8")).hexdigest()


def audit_day_label(now: datetime | None = None) -> str:
    current = now if now is not None else datetime.now(UTC)
    return current.date().isoformat()


def rejection_record_to_dict(record: RejectionRecord) -> dict[str, Any]:
    return asdict(record)


def emit_rejection(out_fh: TextIO, record: RejectionRecord) -> None:
    out_fh.write(json.dumps(rejection_record_to_dict(record), sort_keys=True) + "\n")
    out_fh.flush()


def admission_state_update(
    *,
    device_key: str,
    device_table_entry: dict[str, Any],
    replay_state: Any,
    accepted_fc: int,
    observed_at: datetime,
    msg_type: int,
    flags: int,
) -> AdmissionStateUpdate:
    highest_fc_seen = getattr(replay_state, "highest_fc_seen", None)
    if isinstance(highest_fc_seen, int):
        next_highest = int(highest_fc_seen)
    else:
        next_highest = max(
            int(device_table_entry.get("highest_fc_seen", -1)), accepted_fc
        )
    return AdmissionStateUpdate(
        device_key=device_key,
        highest_fc_seen=next_highest,
        last_seen=observed_at.isoformat(),
        msg_type=msg_type,
        flags=flags,
    )


def apply_admission_state_update(
    device_table: dict[str, Any],
    update: AdmissionStateUpdate,
) -> None:
    entry = device_table.get(update.device_key, {})
    if not isinstance(entry, dict):
        entry = {}
    entry["highest_fc_seen"] = update.highest_fc_seen
    entry["last_seen"] = update.last_seen
    entry["msg_type"] = update.msg_type
    entry["flags"] = update.flags
    device_table[update.device_key] = entry


__all__ = [
    "AdmissionStateUpdate",
    "REJECTION_SOURCE_DECRYPT",
    "REJECTION_SOURCE_PARSE",
    "REJECTION_SOURCE_REPLAY",
    "REJECTION_REASON_TAXONOMY",
    "REJECTION_SOURCE_TAXONOMY",
    "RejectionRecord",
    "admission_state_update",
    "apply_admission_state_update",
    "audit_day_label",
    "emit_rejection",
    "hash_rejected_line",
    "rejection_record_to_dict",
]
