#!/usr/bin/env python3
"""Tests for release-contract constants exposed through trackone_core."""

from __future__ import annotations

import importlib
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


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


def test_verifier_export_policy_lives_in_rust_contract() -> None:
    subprocess.run(
        [
            "cargo",
            "test",
            "--package",
            "trackone-evidence",
            "rust_verifier_accepts_bundle_without_python_runtime",
        ],
        check=True,
    )
