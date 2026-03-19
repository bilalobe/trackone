#!/usr/bin/env python3
"""Helpers for tamper-evident local input files."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from trackone_core.ledger import normalize_hex64, sha256_hex


def sha256_sidecar_path(path: Path) -> Path:
    """Return the detached SHA-256 sidecar path for `path`."""
    return path.with_name(f"{path.name}.sha256")


def _parse_declared_digest(sidecar_path: Path, *, expected_name: str) -> str:
    try:
        raw = sidecar_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(
            f"failed to read SHA-256 sidecar {sidecar_path}: {exc}"
        ) from exc
    if not raw:
        raise ValueError(f"empty SHA-256 sidecar: {sidecar_path}")

    parts = raw.split()
    declared = cast(str, normalize_hex64(parts[0]))
    if len(parts) >= 2 and parts[-1] != expected_name:
        raise ValueError(
            f"SHA-256 sidecar filename mismatch for {sidecar_path}: "
            f"expected {expected_name}, got {parts[-1]}"
        )
    return declared


def write_sha256_sidecar(path: Path) -> Path:
    """Write a detached SHA-256 sidecar in sha256sum-compatible format."""
    sidecar = sha256_sidecar_path(path)
    digest = sha256_hex(path.read_bytes())
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return sidecar


def require_sha256_sidecar(path: Path, *, label: str | None = None) -> None:
    """Require a detached SHA-256 sidecar and verify it against the file bytes."""
    display = label or path.name
    sidecar = sha256_sidecar_path(path)
    if not path.exists():
        raise ValueError(f"{display} not found: {path}")
    if not sidecar.exists():
        raise ValueError(f"{display} SHA-256 sidecar missing: {sidecar}")

    declared = _parse_declared_digest(sidecar, expected_name=path.name)
    actual = sha256_hex(path.read_bytes())
    if actual != declared:
        raise ValueError(
            f"{display} SHA-256 mismatch: expected {declared}, got {actual}"
        )
