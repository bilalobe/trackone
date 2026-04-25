"""Shared verifier-summary helpers for TrackOne verification surfaces."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .release import disclosure_label, publicly_recomputable

STATUS_VERIFIED = "verified"
STATUS_FAILED = "failed"
STATUS_MISSING = "missing"
STATUS_PENDING = "pending"
STATUS_SKIPPED = "skipped"

CHANNEL_OTS = "ots"
CHANNEL_TSA = "tsa"
CHANNEL_PEERS = "peers"
CHANNEL_SCITT = "scitt"
PUBLICATION_CHANNELS = (CHANNEL_OTS, CHANNEL_TSA, CHANNEL_PEERS, CHANNEL_SCITT)

CHECK_DAY_ARTIFACT = "day_artifact_validation"
CHECK_FACT_RECOMPUTE = "fact_level_recompute"
CHECK_MANIFEST = "verification_manifest_validation"
CHECK_BATCH_METADATA = "batch_metadata_validation"
CHECK_OTS = "ots_verification"
CHECK_TSA = "tsa_verification"
CHECK_PEERS = "peer_signature_verification"

PORTABLE_VERIFIER_SUMMARY_FIELDS = (
    "policy",
    "verification",
    "checks",
    "verification_scope_exercised",
    "checks_executed",
    "checks_skipped",
    "channels",
    "manifest",
    "overall",
)


def verification_channel(
    enabled: bool,
    status: str,
    reason: str = "",
) -> dict[str, Any]:
    return {"enabled": enabled, "status": status, "reason": reason}


def compute_publication_overall_status(
    *,
    policy_mode: str,
    channels: dict[str, Any] | Any,
) -> str:
    """Reduce optional publication-channel statuses into a verifier run status."""
    if policy_mode == "strict":
        for item in _publication_channel_values(channels):
            if item.get("enabled", False) and item.get("status") != STATUS_VERIFIED:
                return "failed"
        return "success"

    ots = _publication_channel(channels, CHANNEL_OTS)
    if ots.get("enabled", False) and ots.get("status") in {
        STATUS_FAILED,
        STATUS_MISSING,
    }:
        return "failed"
    return "success"


def publication_channel_env_overrides(anchoring: dict[str, Any]) -> dict[str, str]:
    """Return env overrides for channel enablement declared in a manifest."""
    channels = anchoring.get("channels")
    if not isinstance(channels, dict):
        return {}

    env_names = {
        CHANNEL_OTS: "ANCHOR_OTS_ENABLED",
        CHANNEL_TSA: "ANCHOR_TSA_ENABLED",
        CHANNEL_PEERS: "ANCHOR_PEERS_ENABLED",
        CHANNEL_SCITT: "ANCHOR_SCITT_ENABLED",
    }
    overrides: dict[str, str] = {}
    for name, env_name in env_names.items():
        channel = channels.get(name)
        if isinstance(channel, dict):
            enabled = channel.get("enabled")
            if isinstance(enabled, bool):
                overrides[env_name] = "1" if enabled else "0"
    return overrides


def _publication_channel(channels: Any, name: str) -> dict[str, Any]:
    if not isinstance(channels, dict):
        return {}
    item = channels.get(name)
    return item if isinstance(item, dict) else {}


def _publication_channel_values(channels: Any) -> list[dict[str, Any]]:
    if not isinstance(channels, dict):
        return []
    return [item for item in channels.values() if isinstance(item, dict)]


def portable_verifier_summary(summary: dict[str, Any]) -> dict[str, Any]:
    portable: dict[str, Any] = {}
    for key in PORTABLE_VERIFIER_SUMMARY_FIELDS:
        value = summary.get(key)
        if value is not None:
            portable[key] = json.loads(json.dumps(value))
    return portable


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
            CHANNEL_OTS: verification_channel(
                ots_enabled,
                STATUS_PENDING if ots_enabled else STATUS_SKIPPED,
                "not-run" if ots_enabled else "disabled",
            ),
            CHANNEL_TSA: verification_channel(
                tsa_enabled,
                STATUS_PENDING if tsa_enabled else STATUS_SKIPPED,
                "not-run" if tsa_enabled else "disabled",
            ),
            CHANNEL_PEERS: verification_channel(
                peers_enabled,
                STATUS_PENDING if peers_enabled else STATUS_SKIPPED,
                "not-run" if peers_enabled else "disabled",
            ),
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


def local_verification_failure(summary: dict[str, Any] | None) -> str | None:
    """Return a stable refusal reason when local integrity checks did not complete."""
    if not isinstance(summary, dict):
        return "summary-missing"

    manifest = summary.get("manifest")
    if not isinstance(manifest, dict) or manifest.get("status") != "present":
        return "manifest-missing"

    checks_executed = summary.get("checks_executed")
    executed = (
        {item for item in checks_executed if isinstance(item, str)}
        if isinstance(checks_executed, list)
        else set()
    )
    for required in (CHECK_DAY_ARTIFACT, CHECK_MANIFEST, CHECK_BATCH_METADATA):
        if required not in executed:
            return f"{required}-not-executed"

    checks = summary.get("checks")
    if not isinstance(checks, dict):
        return "checks-missing"
    if checks.get("artifact_valid") is not True:
        return "artifact-invalid"
    if checks.get("meta_valid") is not True:
        return "meta-invalid"

    verification = summary.get("verification")
    disclosure_class = (
        verification.get("disclosure_class") if isinstance(verification, dict) else None
    )
    if disclosure_class == "A":
        if CHECK_FACT_RECOMPUTE not in executed:
            return "fact_level_recompute-not-executed"
        if checks.get("root_match") is not True:
            return "fact-root-mismatch"

    return None


__all__ = [
    "CHECK_BATCH_METADATA",
    "CHECK_DAY_ARTIFACT",
    "CHECK_FACT_RECOMPUTE",
    "CHECK_MANIFEST",
    "CHECK_OTS",
    "CHECK_PEERS",
    "CHECK_TSA",
    "CHANNEL_OTS",
    "CHANNEL_PEERS",
    "CHANNEL_SCITT",
    "CHANNEL_TSA",
    "PUBLICATION_CHANNELS",
    "STATUS_FAILED",
    "STATUS_MISSING",
    "STATUS_PENDING",
    "STATUS_SKIPPED",
    "STATUS_VERIFIED",
    "build_verifier_summary",
    "compute_publication_overall_status",
    "local_verification_failure",
    "portable_verifier_summary",
    "publication_channel_env_overrides",
    "record_executed_check",
    "record_skipped_check",
    "refresh_publicly_recomputable",
    "set_channel",
    "set_manifest_status",
    "verification_channel",
]
