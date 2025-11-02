#!/usr/bin/env python3
"""
ots_anchor.py

Anchor a day blob using OpenTimestamps (OTS) for public verifiability.

This script creates a cryptographic timestamp proof by submitting the day.bin
SHA-256 hash to Bitcoin blockchain via OpenTimestamps attestation servers.

The OTS proof allows anyone to independently verify that the day blob existed
at a specific time, without trusting the gateway operator.

Workflow:
1. stamp: Submit day.bin to OTS servers → creates .ots proof (pending)
2. upgrade: Poll OTS servers to update pending → confirmed (with Bitcoin block)
3. verify: Independently verify that proof anchors the day.bin hash

For M#1, this script gracefully degrades to a placeholder if the OTS client
is not installed, allowing development/testing without Bitcoin dependencies.

References:
- ADR-003: Daily OTS Anchoring
- OpenTimestamps: https://opentimestamps.org/

Usage:
    # Stamp a day blob
    python ots_anchor.py out/site_demo/day/2025-10-07.bin

    # Later, upgrade pending proofs
    ots upgrade out/site_demo/day/2025-10-07.bin.ots

    # Verify proof
    ots verify out/site_demo/day/2025-10-07.bin.ots
"""
from __future__ import annotations

import argparse
import subprocess  # nosec: B404 - invoking a vetted external tool via validated args
from pathlib import Path


def ots_stamp(day_bin_path: Path, ots_path: Path) -> None:
    """Stamp the day blob using OpenTimestamps CLI, or write a placeholder if not available.

    Contract:
    - Input: day_bin_path (Path to .bin), ots_path (.bin.ots target path)
    - Behavior: attempt `ots stamp <bin>`; on any failure, write placeholder proof.
    - Success: if the OTS command doesn't produce the .ots file, write placeholder.
    """
    try:
        # Attempt to invoke the OTS client. Tests expect the plain command name here.
        # nosec: B603 - call is to a fixed executable name with local file argument; no shell.
        subprocess.run(["ots", "stamp", str(day_bin_path)], check=True)  # nosec
        # OTS client typically writes <bin>.ots; ensure something exists for downstream steps.
        if not ots_path.exists():
            ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")
    except subprocess.CalledProcessError:
        # Non-zero exit from the OTS client → fallback placeholder
        ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")
    except OSError:
        # Command not found, permission issue, etc. → fallback placeholder
        ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Anchor a day blob using OpenTimestamps (OTS)"
    )
    p.add_argument("day_bin", type=Path, help="Path to day/YYYY-MM-DD.bin blob")
    args = p.parse_args(argv)

    day_bin_path = args.day_bin
    ots_path = day_bin_path.with_suffix(day_bin_path.suffix + ".ots")
    ots_stamp(day_bin_path, ots_path)
    print(f"OTS proof written: {ots_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
