"""Release-contract constants and helpers shared across Python surfaces."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

try:
    from . import _native as _native
except ImportError:
    _native = None


def _native_str(name: str, default: str) -> str:
    value = getattr(_native, name, default)
    return value if isinstance(value, str) else default


DEFAULT_COMMITMENT_PROFILE_ID = _native_str(
    "DEFAULT_COMMITMENT_PROFILE_ID",
    "trackone-canonical-cbor-v1",
)

DISCLOSURE_CLASS_LABELS: dict[str, str] = {
    _native_str("DISCLOSURE_CLASS_A", "A"): _native_str(
        "DISCLOSURE_CLASS_A_LABEL",
        "public-recompute",
    ),
    _native_str("DISCLOSURE_CLASS_B", "B"): _native_str(
        "DISCLOSURE_CLASS_B_LABEL",
        "partner-audit",
    ),
    _native_str("DISCLOSURE_CLASS_C", "C"): _native_str(
        "DISCLOSURE_CLASS_C_LABEL",
        "anchor-only-evidence",
    ),
}


def disclosure_label(disclosure_class: str) -> str:
    """Return the operator-facing label for a disclosure class."""
    return DISCLOSURE_CLASS_LABELS.get(disclosure_class, disclosure_class)


def publicly_recomputable(
    disclosure_class: str,
    *,
    artifact_valid: Any,
    root_match: Any,
) -> bool:
    """Return whether the current verification result supports public recompute."""
    return disclosure_class == "A" and artifact_valid is True and root_match is True


def verification_bundle_from_summary(
    verifier_summary: Mapping[str, Any] | None,
    *,
    disclosure_class: str = "A",
    commitment_profile_id: str = DEFAULT_COMMITMENT_PROFILE_ID,
) -> dict[str, Any]:
    """Build the manifest verification bundle from verifier summary data."""
    verification_bundle: dict[str, Any] = {
        "disclosure_class": disclosure_class,
        "commitment_profile_id": commitment_profile_id,
        "checks_executed": [],
        "checks_skipped": [],
    }
    if verifier_summary is None:
        return verification_bundle

    verification = verifier_summary.get("verification")
    if isinstance(verification, Mapping):
        cls = verification.get("disclosure_class")
        prof = verification.get("commitment_profile_id")
        if isinstance(cls, str) and cls:
            verification_bundle["disclosure_class"] = cls
        if isinstance(prof, str) and prof:
            verification_bundle["commitment_profile_id"] = prof

    checks_executed = verifier_summary.get("checks_executed")
    checks_skipped = verifier_summary.get("checks_skipped")
    if isinstance(checks_executed, list):
        verification_bundle["checks_executed"] = checks_executed
    if isinstance(checks_skipped, list):
        verification_bundle["checks_skipped"] = checks_skipped
    return verification_bundle


__all__ = [
    "DEFAULT_COMMITMENT_PROFILE_ID",
    "DISCLOSURE_CLASS_LABELS",
    "disclosure_label",
    "publicly_recomputable",
    "verification_bundle_from_summary",
]
