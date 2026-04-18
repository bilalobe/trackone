#!/usr/bin/env python3
"""Helpers for interpreting verifier summaries on the local integrity path."""

from __future__ import annotations

from typing import Any

from trackone_core.verification import (
    CHECK_BATCH_METADATA,
    CHECK_DAY_ARTIFACT,
    CHECK_FACT_RECOMPUTE,
    CHECK_MANIFEST,
)


def local_verification_failure(summary: dict[str, Any] | None) -> str | None:
    """Return a short failure reason when local integrity checks did not complete."""
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
