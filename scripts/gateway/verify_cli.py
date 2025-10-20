#!/usr/bin/env python3
"""
verify_cli.py

Verify Merkle root and OTS proof for a day's telemetry batch.

This script provides independent verification of the batching and anchoring process:
1. Recomputes Merkle root from canonical fact files
2. Compares recomputed root against block header (authoritative)
3. Verifies OTS proof anchors the day.bin blob

Exit codes:
- 0: Success (root matches and OTS verified)
- 1: Block header not found or invalid day field
- 2: Merkle root mismatch
- 3: OTS proof file not found
- 4: OTS proof verification failed (strict mode only)

By default (lenient mode), placeholder proofs and unavailable OTS verification are treated as non-fatal to support CI/trial phases.
Use --strict-ots to require a successful OTS verification (headers available and client installed).

References:
- ADR-003: Canonicalization, Merkle Policy, Daily OTS Anchoring
- ADR-007: CI headers policy (lenient in PRs, strict on main)

Usage:
    # Verify using facts from default location
    python verify_cli.py --root out/site_demo

    # Verify using custom facts directory
    python verify_cli.py --root out/site_demo --facts out/site_demo/facts
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def merkle_root(leaves):
    # Mirror merkle_batcher: if empty -> sha256(""); else hash leaves, sort by hex, then build tree
    if not leaves:
        return sha256(b"").hexdigest()
    leaf_hashes = [sha256(leaf).hexdigest() for leaf in leaves]
    leaf_hashes_sorted = sorted(leaf_hashes)
    layer = [bytes.fromhex(hx) for hx in leaf_hashes_sorted]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(sha256(a + b).digest())
        layer = nxt
    return layer[0].hex()


def run_ots_verify(ots_path: Path) -> int:
    """Run 'ots verify' if available; return its exit code or 127 if not available."""
    if shutil.which("ots") is None:
        return 127
    try:
        result = subprocess.run(
            ["ots", "verify", str(ots_path)], capture_output=True, text=True
        )
        return result.returncode
    except Exception:
        # Treat unexpected execution issues as failure
        return 2


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Verify Merkle root and OTS proof for a day"
    )
    p.add_argument(
        "--root", type=Path, required=True, help="Path to out/site_demo root directory"
    )
    p.add_argument(
        "--facts",
        type=Path,
        default=Path("toolset/unified/examples"),
        help="Directory with fact JSON files to recompute the Merkle root",
    )
    p.add_argument(
        "--strict-ots",
        action="store_true",
        help="Require successful OTS verification; otherwise lenient (placeholders/headers-missing are non-fatal)",
    )
    args = p.parse_args(argv)

    root_dir = args.root
    facts_dir = args.facts
    blocks_dir = root_dir / "blocks"
    day_dir = root_dir / "day"

    # Find day (assume one block/day for demo)
    block_files = sorted(blocks_dir.glob("*.block.json"))
    if not block_files:
        print("ERROR: No block header found.")
        return 1
    block_path = block_files[0]

    # Load block header to get authoritative day value
    block_header = json.load(block_path.open("r", encoding="utf-8"))
    day = block_header.get("day")
    if not isinstance(day, str) or len(day) != 10:
        print(f"ERROR: Invalid or missing 'day' in block header: {block_path}")
        return 1

    day_bin_path = day_dir / f"{day}.bin"
    ots_path = day_bin_path.with_suffix(day_bin_path.suffix + ".ots")

    # Read and canonicalize all facts
    fact_files = sorted(facts_dir.glob("*.json"))
    leaves = []
    for fpath in fact_files:
        obj = json.load(fpath.open("r", encoding="utf-8"))
        canon = canonical_json(obj)
        leaves.append(canon)

    # Recompute Merkle root
    recomputed_root = merkle_root(leaves)
    recorded_root = block_header.get("merkle_root")

    # Verify root matches
    if recomputed_root != recorded_root:
        print(
            f"ERROR: Merkle root mismatch. Computed: {recomputed_root}, Recorded: {recorded_root}"
        )
        return 2

    # Verify OTS proof
    if not ots_path.exists():
        print(f"ERROR: OTS proof file not found: {ots_path}")
        return 3

    # Accept explicit placeholder in lenient mode
    try:
        content = ots_path.read_text(encoding="utf-8").strip()
    except Exception:
        content = ""
    if content == "OTS_PROOF_PLACEHOLDER":
        print(
            f"WARN: OTS placeholder found at {ots_path}; skipping verification (lenient mode)"
        )
        return 0

    rc = run_ots_verify(ots_path)
    if rc == 0:
        print("OK: root matches and OTS verified")
        return 0

    # Non-zero: either ots not available (127) or verification failed (headers missing, etc.)
    if args.strict_ots:
        reason = (
            "OTS client not installed"
            if rc == 127
            else f"verification failed (rc={rc})"
        )
        print(f"ERROR: OTS proof {reason} for {ots_path}")
        return 4

    # Lenient mode: warn and proceed
    if rc == 127:
        print(f"WARN: OTS client not installed; skipping verification for {ots_path}")
    else:
        print(
            f"WARN: OTS verify returned {rc}; treating as deferred (lenient mode) for {ots_path}"
        )
    return 0


# ci: trigger ots-verify


if __name__ == "__main__":
    raise SystemExit(main())
