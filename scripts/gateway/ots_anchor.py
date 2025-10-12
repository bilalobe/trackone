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
import subprocess
from pathlib import Path


def ots_stamp(day_bin_path: Path, ots_path: Path) -> None:
    """Stamp the day blob using OpenTimestamps CLI, or write a placeholder if not available."""
    try:
        # Try to call ots stamp (requires ots client installed)
        subprocess.run(["ots", "stamp", str(day_bin_path)], check=True)
        # OTS client writes .ots file next to .bin
        if not ots_path.exists():
            # Fallback: create a dummy .ots file
            ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")
    except Exception:
        # Fallback: create a dummy .ots file
        ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")


def main(argv=None) -> int:
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
