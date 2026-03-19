#!/usr/bin/env python3
"""Shared verifier-facing manifest naming helpers."""

from __future__ import annotations

from pathlib import Path

VERIFY_MANIFEST_SCHEMA = "verify_manifest"
VERIFY_MANIFEST_SUFFIX = ".verify.json"


def verify_manifest_path(day_dir: Path, day: str) -> Path:
    return day_dir / f"{day}{VERIFY_MANIFEST_SUFFIX}"


def manifest_candidates(day_dir: Path, day: str) -> list[tuple[str, Path, str]]:
    return [
        ("verify_manifest", verify_manifest_path(day_dir, day), VERIFY_MANIFEST_SCHEMA)
    ]
