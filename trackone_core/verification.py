"""Shared verifier-summary helpers for TrackOne verification surfaces."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .release import disclosure_label, publicly_recomputable

STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_MISSING = "missing"
STATUS_PENDING = "pending"
STATUS_SKIPPED = "skipped"

CHECK_DAY_ARTIFACT = "day_artifact_validation"
CHECK_FACT_RECOMPUTE = "fact_level_recompute"
CHECK_MANIFEST = "verification_manifest_validation"
CHECK_BATCH_METADATA = "batch_metadata_validation"
CHECK_OTS = "ots_verification"
CHECK_TSA = "tsa_verification"
CHECK_PEERS = "peer_signature_verification"


def verification_channel(
    enabled: bool,
    status: str,
    reason: str = "",
) -> dict[str, Any]:
    return {"enabled": enabled, "status": status, "reason": reason}


def build_verifier_summary(
    *,
    policy_mode: str,
    disclosure_class: str,
    commitment_profile_id: str,
    manifest_schema: str,
    block_path: Path,
    day_artifact: Path,
    ots_path: Path,
    manifest_path: Path,
    ots_enabled: bool,
    tsa_enabled: bool,
    peers_enabled: bool,
) -> dict[str, Any]:
    return {
        "policy": {"mode": policy_mode},
        "verification": {
            "disclosure_class": disclosure_class,
            "disclosure_label": disclosure_label(disclosure_class),
            "commitment_profile_id": commitment_profile_id,
            "publicly_recomputable": False,
        },
        "manifest": {
            "status": "missing",
            "source": None,
            "schema": manifest_schema,
        },
        "artifacts": {
            "block": str(block_path),
            "day_cbor": str(day_artifact),
            "day_ots": str(ots_path),
            "verification_manifest": str(manifest_path),
        },
        "checks": {
            "root_match": None,
            "artifact_valid": False,
            "meta_valid": True,
        },
        "verification_scope_exercised": [],
        "checks_executed": [],
        "checks_skipped": [],
        "channels": {
            "ots": verification_channel(ots_enabled, STATUS_SKIPPED, "disabled"),
            "tsa": verification_channel(tsa_enabled, STATUS_SKIPPED, "disabled"),
            "peers": verification_channel(peers_enabled, STATUS_SKIPPED, "disabled"),
        },
        "overall": "failed",
    }


def record_executed_check(summary: dict[str, Any], check: str) -> None:
    checks = summary.setdefault("checks_executed", [])
    if isinstance(checks, list):
        checks.append(check)
    scope = summary.setdefault("verification_scope_exercised", [])
    if isinstance(scope, list) and check not in scope:
        scope.append(check)


def record_skipped_check(summary: dict[str, Any], check: str, reason: str) -> None:
    checks = summary.setdefault("checks_skipped", [])
    if isinstance(checks, list):
        checks.append({"check": check, "reason": reason})


def set_manifest_status(
    summary: dict[str, Any],
    *,
    status: str,
    source: str | None,
    schema: str,
) -> None:
    summary["manifest"] = {
        "status": status,
        "source": source,
        "schema": schema,
    }


def set_channel(
    summary: dict[str, Any],
    name: str,
    *,
    enabled: bool,
    status: str,
    reason: str,
) -> None:
    channels = summary.get("channels")
    if not isinstance(channels, dict):
        return
    channels[name] = verification_channel(enabled, status, reason)


def refresh_publicly_recomputable(summary: dict[str, Any]) -> None:
    verification = summary.get("verification")
    checks = summary.get("checks")
    if not isinstance(verification, dict) or not isinstance(checks, dict):
        return
    verification["publicly_recomputable"] = publicly_recomputable(
        str(verification.get("disclosure_class", "")),
        artifact_valid=checks.get("artifact_valid"),
        root_match=checks.get("root_match"),
    )


__all__ = [
    "CHECK_BATCH_METADATA",
    "CHECK_DAY_ARTIFACT",
    "CHECK_FACT_RECOMPUTE",
    "CHECK_MANIFEST",
    "CHECK_OTS",
    "CHECK_PEERS",
    "CHECK_TSA",
    "STATUS_FAILED",
    "STATUS_MISSING",
    "STATUS_PENDING",
    "STATUS_SKIPPED",
    "STATUS_VERIFIED",
    "build_verifier_summary",
    "record_executed_check",
    "record_skipped_check",
    "refresh_publicly_recomputable",
    "set_channel",
    "set_manifest_status",
    "verification_channel",
]
