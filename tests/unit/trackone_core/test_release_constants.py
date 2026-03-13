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


def test_release_constants_have_safe_python_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    release = importlib.import_module("trackone_core.release")

    assert release.DEFAULT_COMMITMENT_PROFILE_ID == "trackone-canonical-cbor-v1"
    assert {
        "A": "public-recompute",
        "B": "partner-audit",
        "C": "anchor-only-evidence",
    } == release.DISCLOSURE_CLASS_LABELS


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
