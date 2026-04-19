#!/usr/bin/env python3
"""Tests for Rust-backed constants exposed through trackone_core."""

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


def test_constants_have_safe_python_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_modules("trackone_core")
    monkeypatch.setitem(sys.modules, "trackone_core._native", None)  # type: ignore[arg-type]

    constants = importlib.import_module("trackone_core.constants")

    assert constants.INGEST_PROFILE_RUST_POSTCARD_V1 == "rust-postcard-v1"
    assert constants.DEFAULT_INGEST_PROFILE == "rust-postcard-v1"
    assert constants.INGEST_PROFILES == ("rust-postcard-v1",)
    assert constants.FRAMED_FACT_MSG_TYPE == 1
    assert constants.OTS_VERIFY_TIMEOUT_SECS == 30


def test_constants_prefer_native_exports(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_modules("trackone_core")

    native = types.ModuleType("trackone_core._native")
    native.INGEST_PROFILE_RUST_POSTCARD_V1 = "rust-postcard-v1"
    native.FRAMED_FACT_MSG_TYPE = 1
    native.OTS_VERIFY_TIMEOUT_SECS = 30
    monkeypatch.setitem(sys.modules, "trackone_core._native", native)

    constants = importlib.import_module("trackone_core.constants")

    assert constants.INGEST_PROFILE_RUST_POSTCARD_V1 == "rust-postcard-v1"
    assert constants.DEFAULT_INGEST_PROFILE == "rust-postcard-v1"
    assert constants.INGEST_PROFILES == ("rust-postcard-v1",)
    assert constants.FRAMED_FACT_MSG_TYPE == 1
    assert constants.OTS_VERIFY_TIMEOUT_SECS == 30
