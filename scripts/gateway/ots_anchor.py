#!/usr/bin/env python3
"""
ots_anchor.py

Anchor a day artifact using OpenTimestamps (OTS) for public verifiability.

This script creates a cryptographic timestamp proof by submitting the day artifact
SHA-256 hash to OpenTimestamps attestation servers. It now also emits a
sidecar metadata file describing the artifact and the proof. The sidecar is
intended to be the authoritative link between an artifact and its proof and
should be considered immutable once created.

Files produced:
- <day>.cbor.ots        (binary or placeholder proof)
- <artifact-dir>/<day>.ots.meta.json  (metadata sidecar with artifact path and SHA-256)

The metadata format is defined by toolset/unified/schemas/ots_meta.schema.json
and includes `artifact`, `artifact_sha256`, and `ots_proof` entries.

Usage:
    ots_anchor.ots_stamp(day_artifact_path, ots_path, meta_dir=None)

When called from a pipeline, the default `meta_dir` is the day artifact
directory itself, so `out/site_demo/` remains self-contained.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess  # nosec B404

# Reason: invoking a vetted external tool via validated args.
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
    return subprocess.run(args, check=True, env=env)  # nosec B603


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
        out = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
        if out.returncode == 0:
            ver = out.stdout
            if not isinstance(ver, str):
                ver = str(ver)
            ver = ver.strip()
            return ver.splitlines()[0] if ver else None
    except (subprocess.CalledProcessError, OSError):
        pass  # ots-cli tool not available or failed; silently skip version check
    return None


def _write_meta_for_day(
    day: str,
    day_bin_path: Path,
    ots_path: Path,
    meta_dir: Path,
) -> Path:
    """Create the ots_meta sidecar in `meta_dir` for the provided day and return the path.

    For day-local metadata (`meta_dir.name == "day"`), the `artifact` and
    `ots_proof` fields are stored relative to the parent bundle/workspace root
    so they resolve cleanly from `out/site_demo/` or exported evidence bundle
    roots. For other layouts, paths are relative to `meta_dir`.
    """
    meta_dir.mkdir(parents=True, exist_ok=True)
    repo_root = (
        meta_dir.resolve().parent if meta_dir.name == "day" else meta_dir.resolve()
    )

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

    meta_path = meta_dir / f"{day}.ots.meta.json"
    meta_path.write_text(
        json.dumps(meta, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return meta_path


def ots_stamp(
    day_bin_path: Path,
    ots_path: Path,
    meta_dir: Path | None = None,
) -> None:
    """Stamp the day artifact using OpenTimestamps CLI, or write a placeholder if not available.

    Contract:
    - Input: day_bin_path (Path to day artifact), ots_path (<artifact>.ots target path)
    - Behavior: attempt `ots stamp <bin>`; on any failure, write placeholder proof.
    - Additionally: write a metadata sidecar to `meta_dir` (if provided) or next
      to the day artifact by default.

    When OTS_STATIONARY_STUB=1 is set in the environment, this function does not
    call the real `ots` binary. Instead, it writes a deterministic stub .ots file
    and a matching ots_meta sidecar. This is intended for tests and offline CI.
    """
    # Stationary stub mode: never call the real ots client.
    if os.environ.get("OTS_STATIONARY_STUB") == "1":
        if meta_dir is None:
            meta_dir = day_bin_path.parent
        meta_dir.mkdir(parents=True, exist_ok=True)

        # Use hex ASCII for the stationary stub so it is human-readable and
        # verifiable against the artifact_sha256 stored in the sidecar.
        artifact_sha = sha256(day_bin_path.read_bytes()).hexdigest()
        payload = f"STATIONARY-OTS:{artifact_sha}\n".encode()
        ots_path.write_bytes(payload)

        _write_meta_for_day(day_bin_path.stem, day_bin_path, ots_path, meta_dir)
        print(f"[stationary] Wrote OTS stub + meta for {day_bin_path.stem}")
        return

    try:
        # Attempt to invoke the OTS client. Tests expect the plain command name here.
        # nosec B603
        # Reason: call is to a fixed executable name with local file argument; no shell.
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

    if meta_dir is None:
        meta_dir = day_bin_path.parent

    # Write sidecar meta file
    day_label = day_bin_path.stem
    try:
        meta_path = _write_meta_for_day(day_label, day_bin_path, ots_path, meta_dir)
        print(f"Wrote OTS meta: {meta_path}")
    except OSError as exc:  # pragma: no cover - defensive
        print(f"[WARN] Failed to write OTS meta sidecar: {exc}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Anchor a day artifact using OpenTimestamps (OTS)"
    )
    p.add_argument(
        "day_bin",
        type=Path,
        help="Path to day/YYYY-MM-DD.cbor artifact (or legacy day blob)",
    )
    p.add_argument(
        "--meta-dir",
        type=Path,
        default=None,
        help="Optional directory to write OTS metadata sidecars (defaults to the artifact directory)",
    )
    p.add_argument(
        "--proofs",
        dest="meta_dir",
        type=Path,
        help=argparse.SUPPRESS,
    )
    args = p.parse_args(argv)

    day_bin_path = args.day_bin
    ots_path = day_bin_path.with_suffix(day_bin_path.suffix + ".ots")
    meta_dir = args.meta_dir
    ots_stamp(day_bin_path, ots_path, meta_dir=meta_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
