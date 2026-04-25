from __future__ import annotations

from trackone_core.verification import local_verification_failure


def test_local_verification_failure_accepts_warn_mode_anchoring_failure() -> None:
    summary = {
        "manifest": {"status": "present"},
        "checks": {
            "artifact_valid": True,
            "meta_valid": True,
            "root_match": True,
        },
        "checks_executed": [
            "day_artifact_validation",
            "verification_manifest_validation",
            "batch_metadata_validation",
            "fact_level_recompute",
            "ots_verification",
        ],
        "verification": {"disclosure_class": "A"},
        "channels": {
            "ots": {
                "enabled": True,
                "status": "failed",
                "reason": "ots-verification-failed",
            }
        },
        "overall": "failed",
    }

    assert local_verification_failure(summary) is None


def test_local_verification_failure_rejects_missing_manifest_validation() -> None:
    summary = {
        "manifest": {"status": "present"},
        "checks": {
            "artifact_valid": True,
            "meta_valid": True,
            "root_match": True,
        },
        "checks_executed": [
            "day_artifact_validation",
            "batch_metadata_validation",
            "fact_level_recompute",
        ],
        "verification": {"disclosure_class": "A"},
    }

    assert (
        local_verification_failure(summary)
        == "verification_manifest_validation-not-executed"
    )
