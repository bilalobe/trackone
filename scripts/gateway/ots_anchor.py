#!/usr/bin/env python3
"""
ots_anchor.py

Anchor a day blob using OpenTimestamps (OTS) for public verifiability.

This script creates a cryptographic timestamp proof by submitting the day.bin
SHA-256 hash to OpenTimestamps attestation servers. It now also emits a
sidecar metadata file describing the artifact and the proof. The sidecar is
intended to be the authoritative link between an artifact and its proof and
should be considered immutable once created.

Files produced:
- <day>.bin.ots        (binary or placeholder proof)
- proofs/<day>.ots.meta.json  (metadata sidecar with artifact path and SHA-256)

The metadata format is defined by toolset/unified/schemas/ots_meta.schema.json
and includes `artifact`, `artifact_sha256`, and `ots_proof` entries.

Usage:
    ots_anchor.ots_stamp(day_bin_path, ots_path, proofs_dir=None)

When called from a pipeline, pass `proofs_dir` pointing to the repository's
`proofs/` directory (e.g., out_root.parent / 'proofs') so the sidecar is colocated
with other evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess  # nosec: B404 - invoking a vetted external tool via validated args
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

OTS_PROOF_PLACEHOLDER = "OTS_PROOF_PLACEHOLDER\n"


def _run_ots(args: list[str]) -> subprocess.CompletedProcess[bytes]:
    """Run the ots client, honoring OTS_CALENDARS if set.

    This helper centralizes environment handling so callers do not need to
    worry about forwarding calendar configuration.
    """
    env = os.environ.copy()
    calendars = env.get("OTS_CALENDARS")
    if calendars:
        env["OTS_CALENDARS"] = calendars
    return subprocess.run(args, check=True, env=env)  # nosec


def _find_repo_root(path: Path) -> Path:
    """Try to find the repository root by looking for pyproject.toml or .git.

    Falls back to current working directory if not found.
    """
    cur = path.resolve()
    for p in [cur] + list(cur.parents):
        if (p / "pyproject.toml").exists() or (p / ".git").exists():
            return p
    return Path.cwd().resolve()


def _ots_client_version() -> str | None:
    """Try to get the ots client version string if available."""
    import shutil

    ots_exe = shutil.which("ots")
    if not ots_exe:
        return None
    try:
        cmd = [ots_exe, "--version"]
        out = subprocess.run(cmd, capture_output=True, text=True)  # nosec
        if out.returncode == 0:
            ver = out.stdout
            if not isinstance(ver, str):
                ver = str(ver)
            ver = ver.strip()
            return ver.splitlines()[0] if ver else None
    except Exception:
        pass
    return None


def _write_meta_for_day(
    day: str,
    day_bin_path: Path,
    ots_path: Path,
    proofs_dir: Path,
    milestone: str = "m4",
) -> Path:
    """Create the ots_meta sidecar in `proofs_dir` for the provided day and return the path.

    The `artifact` and `ots_proof` fields are stored as paths relative to the repo root
    (i.e., relative to `proofs_dir.parent`).
    """
    proofs_dir.mkdir(parents=True, exist_ok=True)
    repo_root = proofs_dir.resolve().parent

    # Compute artifact sha256
    artifact_bytes = day_bin_path.read_bytes()
    artifact_sha = sha256(artifact_bytes).hexdigest()

    # Prefer repository-relative paths in metadata for portability. If the day
    # artifact lives outside the repository (common in unit tests with tmpdirs),
    # fall back to absolute paths to avoid breaking.
    try:
        artifact_field = str(day_bin_path.relative_to(repo_root))
    except ValueError:
        artifact_field = str(day_bin_path.resolve())

    try:
        ots_field = str(ots_path.relative_to(repo_root))
    except ValueError:
        ots_field = str(ots_path.resolve())

    # Build metadata object
    meta: dict[str, Any] = {
        "milestone": milestone,
        "day": day,
        "artifact": artifact_field,
        "artifact_sha256": artifact_sha,
        "ots_proof": ots_field,
        "ots_client_version": _ots_client_version() or "unknown",
        "bitcoin": {
            "height": 0,
            "blockhash": "0" * 64,
            # store the artifact sha as a stand-in for merkleroot for now
            "merkleroot": artifact_sha,
        },
        "verified_at_utc": datetime.now(UTC).isoformat(),
    }

    meta_path = proofs_dir / f"{day}.ots.meta.json"
    meta_path.write_text(
        json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return meta_path


def ots_stamp(
    day_bin_path: Path,
    ots_path: Path,
    proofs_dir: Path | None = None,
    milestone: str = "m4",
) -> None:
    """Stamp the day blob using OpenTimestamps CLI, or write a placeholder if not available.

    Contract:
    - Input: day_bin_path (Path to .bin), ots_path (.bin.ots target path)
    - Behavior: attempt `ots stamp <bin>`; on any failure, write placeholder proof.
    - Additionally: write a metadata sidecar to `proofs_dir` (if provided) or to the
      repository's `proofs/` directory discovered from the day blob path.

    When OTS_STATIONARY_STUB=1 is set in the environment, this function does not
    call the real `ots` binary. Instead, it writes a deterministic stub .ots file
    and a matching ots_meta sidecar. This is intended for tests and offline CI.
    """
    # Stationary stub mode: never call the real ots client.
    if os.environ.get("OTS_STATIONARY_STUB") == "1":
        if proofs_dir is None:
            repo_root = _find_repo_root(day_bin_path)
            proofs_dir = repo_root / "proofs"
        proofs_dir.mkdir(parents=True, exist_ok=True)

        # Use hex ASCII for the stationary stub so it is human-readable and
        # verifiable against the artifact_sha256 stored in the sidecar.
        artifact_sha = sha256(day_bin_path.read_bytes()).hexdigest()
        payload = f"STATIONARY-OTS:{artifact_sha}\n".encode()
        ots_path.write_bytes(payload)

        _write_meta_for_day(
            day_bin_path.stem, day_bin_path, ots_path, proofs_dir, milestone
        )
        print(f"[stationary] Wrote OTS stub + meta for {day_bin_path.stem}")
        return

    try:
        # Attempt to invoke the OTS client. Tests expect the plain command name here.
        # nosec: B603 - call is to a fixed executable name with local file argument; no shell.
        _run_ots(["ots", "stamp", str(day_bin_path)])
        # OTS client typically writes <bin>.ots; ensure something exists for downstream steps.
        if not ots_path.exists():
            ots_path.write_text(OTS_PROOF_PLACEHOLDER, encoding="utf-8")
        else:
            # Best-effort: attempt an upgrade to enrich the proof; ignore any failures/timeouts.
            with contextlib.suppress(Exception):
                _run_ots(["ots", "upgrade", str(ots_path)])
    except subprocess.CalledProcessError:
        # Non-zero exit from the OTS client → fallback placeholder
        ots_path.write_text(OTS_PROOF_PLACEHOLDER, encoding="utf-8")
    except OSError:
        # Command not found, permission issue, etc. → fallback placeholder
        ots_path.write_text(OTS_PROOF_PLACEHOLDER, encoding="utf-8")

    # Determine where to write meta: prefer provided proofs_dir; else locate repo root from day_bin
    if proofs_dir is None:
        repo_root = _find_repo_root(day_bin_path)
        proofs_dir = repo_root / "proofs"

    # Write sidecar meta file
    day_label = day_bin_path.stem
    try:
        meta_path = _write_meta_for_day(
            day_label, day_bin_path, ots_path, proofs_dir, milestone
        )
        print(f"Wrote OTS meta: {meta_path}")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[WARN] Failed to write OTS meta sidecar: {exc}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Anchor a day blob using OpenTimestamps (OTS)"
    )
    p.add_argument("day_bin", type=Path, help="Path to day/YYYY-MM-DD.bin blob")
    p.add_argument(
        "--proofs",
        type=Path,
        default=None,
        help="Optional directory to write proofs meta files (defaults to repo_root/proofs)",
    )
    p.add_argument(
        "--milestone",
        type=str,
        default="m5",
        help="Milestone label recorded in the meta sidecar",
    )
    args = p.parse_args(argv)

    day_bin_path = args.day_bin
    ots_path = day_bin_path.with_suffix(day_bin_path.suffix + ".ots")
    proofs_dir = args.proofs
    if proofs_dir is not None:
        proofs_dir = proofs_dir
    ots_stamp(day_bin_path, ots_path, proofs_dir=proofs_dir, milestone=args.milestone)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
