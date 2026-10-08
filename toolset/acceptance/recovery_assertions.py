"""Qualification assertions independent of gateway producer state."""
from __future__ import annotations

from collections import Counter
import hashlib


BOUNDARIES = (
    "ledger_before_commit", "ledger_after_commit", "admission_response",
    "seal_construct", "seal_inserted", "records_copied",
    "timestamp_before_commit", "timestamp_after_commit",
)
REQUIRED_SCENARIOS = (
    *BOUNDARIES, "acknowledged_restart", "lost_response_retry",
    "admission_transaction_error", "sealing_transaction_error",
    "timestamp_transaction_error", "full_storage", "clock_forward",
    "clock_backward", "clock_continuity", "database_disconnect",
    "database_crash", "tsa_outage", "fresh_restore",
)


def assert_occurrences(expected: list[str], actual: list[str]) -> None:
    if Counter(expected) != Counter(actual):
        raise AssertionError("occurrence multiplicity mismatch")


def assert_artifacts(baseline: dict[str, str], current: dict[str, str]) -> None:
    for number, artifact in baseline.items():
        if current.get(number) != artifact:
            raise AssertionError(f"sealed artifact changed or disappeared: {number}")


def assert_chain(snapshot: dict, decode) -> str:
    segments = snapshot["segments"]
    if [int(s["number"]) for s in segments] != list(range(len(segments))):
        raise AssertionError("segment gap or duplicate")
    previous = None
    profile = None
    for row in segments:
        data = bytes.fromhex(row["artifact"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != row["sha256"]:
            raise AssertionError("artifact digest mismatch")
        segment = decode(data)
        if segment["segment_number"] != int(row["number"]):
            raise AssertionError("segment identity mismatch")
        if segment["prev_segment_sha256"] != (bytes.fromhex(previous) if previous else bytes(32)):
            raise AssertionError("predecessor linkage mismatch")
        if segment["close_reason"] != row["reason"]:
            raise AssertionError("unexplained closure")
        records = [r for r in snapshot["records"] if r["segment"] == row["number"]]
        if segment["record_count"] != len(records):
            raise AssertionError("sealed record count mismatch")
        if [int(r["ordinal"]) for r in records] != list(range(len(records))):
            raise AssertionError("record ordinal gap or duplicate")
        if profile is not None and profile != segment["commitment_profile_id"]:
            raise AssertionError("profile changed")
        profile = segment["commitment_profile_id"]
        previous = digest
    state = snapshot["state"]
    if int(state["next"]) != len(segments):
        raise AssertionError("next segment number mismatch")
    if state["predecessor"] != (segments[-1]["artifact"] if segments else None):
        raise AssertionError("producer predecessor mismatch")
    return profile


def assert_complete(report: dict) -> None:
    cases = report["scenarios"]
    if Counter(c["name"] for c in cases) != Counter(REQUIRED_SCENARIOS):
        raise AssertionError("required scenario inventory mismatch")
    if any(c["status"] != "passed" or not c.get("fault_observed")
           or not c.get("verification_reports") for c in cases):
        raise AssertionError("qualification scenario incomplete or failed")
    if not report.get("commit") or not report.get("profile_uuid") or not report.get("source_sha256"):
        raise AssertionError("qualification provenance missing")
