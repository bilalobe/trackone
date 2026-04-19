#!/usr/bin/env python3
"""Tests for release-contract constants exposed through trackone_core."""

from __future__ import annotations

import importlib
import sys
import types

import pytest


def _clear_modules(prefix: str) -> None:
    for key in list(sys.modules):
        if key == prefix or key.startswith(prefix + "."):
            sys.modules.pop(key, None)


@pytest.fixture(autouse=True)
def _isolate_trackone_core_modules() -> None:
    _clear_modules("trackone_core")
    try:
        yield
    finally:
        _clear_modules("trackone_core")


def test_release_constants_have_safe_python_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    release = importlib.import_module("trackone_core.release")

    assert release.DEFAULT_COMMITMENT_PROFILE_ID == "trackone-canonical-cbor-v1"
    assert release.DISCLOSURE_CLASS_LABELS == {
        "A": "public-recompute",
        "B": "partner-audit",
        "C": "anchor-only-evidence",
    }
    assert release.disclosure_label("B") == "partner-audit"
    assert (
        release.publicly_recomputable("A", artifact_valid=True, root_match=True) is True
    )
    assert (
        release.publicly_recomputable("B", artifact_valid=True, root_match=True)
        is False
    )
    assert release.verification_bundle_from_summary(None) == {
        "disclosure_class": "A",
        "commitment_profile_id": "trackone-canonical-cbor-v1",
        "checks_executed": [],
        "checks_skipped": [],
    }


def test_release_constants_prefer_native_exports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")

    native = types.ModuleType("trackone_core._native")
    native.DEFAULT_COMMITMENT_PROFILE_ID = "trackone-canonical-cbor-v1"
    native.DISCLOSURE_CLASS_A = "A"
    native.DISCLOSURE_CLASS_A_LABEL = "public-recompute"
    native.DISCLOSURE_CLASS_B = "B"
    native.DISCLOSURE_CLASS_B_LABEL = "partner-audit"
    native.DISCLOSURE_CLASS_C = "C"
    native.DISCLOSURE_CLASS_C_LABEL = "anchor-only-evidence"
    monkeypatch.setitem(sys.modules, "trackone_core._native", native)

    release = importlib.import_module("trackone_core.release")

    assert release.DEFAULT_COMMITMENT_PROFILE_ID == "trackone-canonical-cbor-v1"
    assert release.DISCLOSURE_CLASS_LABELS["A"] == "public-recompute"
    assert release.DISCLOSURE_CLASS_LABELS["B"] == "partner-audit"
    assert release.DISCLOSURE_CLASS_LABELS["C"] == "anchor-only-evidence"


def test_verification_bundle_from_summary_prefers_verifier_summary_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    release = importlib.import_module("trackone_core.release")

    bundle = release.verification_bundle_from_summary(
        {
            "verification": {
                "disclosure_class": "C",
                "commitment_profile_id": "trackone-canonical-cbor-v2",
            },
            "checks_executed": ["day_artifact_validation"],
            "checks_skipped": [{"check": "fact_level_recompute", "reason": "demo"}],
        },
        disclosure_class="A",
        commitment_profile_id="trackone-canonical-cbor-v1",
    )

    assert bundle == {
        "disclosure_class": "C",
        "commitment_profile_id": "trackone-canonical-cbor-v2",
        "checks_executed": ["day_artifact_validation"],
        "checks_skipped": [{"check": "fact_level_recompute", "reason": "demo"}],
    }


def test_verification_helpers_build_and_update_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    verification = importlib.import_module("trackone_core.verification")

    summary = verification.build_verifier_summary(
        policy_mode="warn",
        disclosure_class="A",
        commitment_profile_id="trackone-canonical-cbor-v1",
        manifest_schema="verify_manifest",
        block_path=__import__("pathlib").Path("/tmp/block.json"),
        day_artifact=__import__("pathlib").Path("/tmp/day.cbor"),
        ots_path=__import__("pathlib").Path("/tmp/day.cbor.ots"),
        manifest_path=__import__("pathlib").Path("/tmp/day.verify.json"),
        ots_enabled=True,
        tsa_enabled=False,
        peers_enabled=False,
    )

    verification.record_executed_check(summary, verification.CHECK_DAY_ARTIFACT)
    verification.record_skipped_check(summary, verification.CHECK_TSA, "disabled")
    verification.set_manifest_status(
        summary,
        status="present",
        source="day.verify.json",
        schema="verify_manifest",
    )
    summary["checks"]["artifact_valid"] = True
    summary["checks"]["root_match"] = True
    verification.refresh_publicly_recomputable(summary)
    verification.set_channel(
        summary,
        "ots",
        enabled=True,
        status=verification.STATUS_VERIFIED,
        reason="ots-verified",
    )

    assert summary["verification"]["disclosure_label"] == "public-recompute"
    assert summary["verification"]["publicly_recomputable"] is True
    assert summary["checks_executed"] == ["day_artifact_validation"]
    assert summary["checks_skipped"] == [
        {"check": "tsa_verification", "reason": "disabled"}
    ]
    assert summary["manifest"]["status"] == "present"
    assert summary["channels"]["ots"] == {
        "enabled": True,
        "status": "verified",
        "reason": "ots-verified",
    }


def test_portable_verifier_summary_keeps_shared_fields_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    verification = importlib.import_module("trackone_core.verification")

    summary = {
        "policy": {"mode": "warn"},
        "verification": {"disclosure_class": "A"},
        "checks": {"root_match": True},
        "verification_scope_exercised": ["day_artifact_validation"],
        "checks_executed": ["day_artifact_validation"],
        "checks_skipped": [{"check": "ots_verification", "reason": "disabled"}],
        "channels": {
            "ots": {"enabled": False, "status": "skipped", "reason": "disabled"}
        },
        "manifest": {"status": "missing", "source": None, "schema": "verify_manifest"},
        "overall": "verified",
        "artifacts": {"block": "/tmp/block.json"},
    }

    assert verification.portable_verifier_summary(summary) == {
        "policy": {"mode": "warn"},
        "verification": {"disclosure_class": "A"},
        "checks": {"root_match": True},
        "verification_scope_exercised": ["day_artifact_validation"],
        "checks_executed": ["day_artifact_validation"],
        "checks_skipped": [{"check": "ots_verification", "reason": "disabled"}],
        "channels": {
            "ots": {"enabled": False, "status": "skipped", "reason": "disabled"}
        },
        "manifest": {"status": "missing", "source": None, "schema": "verify_manifest"},
        "overall": "verified",
    }
