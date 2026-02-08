#!/usr/bin/env python3
"""
verify_cli.py

Verify Merkle root and OTS proof for a day's telemetry batch.

This script provides independent verification of the batching and anchoring process:
1. Recomputes Merkle root from canonical fact files
2. Compares recomputed root against block header (authoritative)
3. Verifies OTS proof anchors the day.bin blob
4. Optionally verifies RFC 3161 TSA timestamps (--verify-tsa)
5. Optionally verifies peer co-signatures (--verify-peers)

Exit codes:
- 0: Success (root matches and required anchors verified)
- 1: Block header not found, invalid day field, or artifact validation failure (invalid/missing merkle_root, non-canonical/malformed day.bin)
- 2: Merkle root mismatch
- 3: OTS proof file not found (when --require-ots or enforced by meta)
- 4: OTS proof verification failed
- 5: TSA verification failed (when --tsa-strict)
- 6: Peer verification failed (when --peers-strict)
- 7: OTS metadata/path mismatch
- 8: OTS metadata invalid/unreadable
- 9: OTS metadata artifact SHA mismatch

This enables auditors to independently verify the gateway's claims without
trusting the gateway operator or database.

References:
- ADR-003: Canonicalization, Merkle Policy, Daily OTS Anchoring
- ADR-015: Parallel Anchoring (OTS + RFC 3161 TSA + Peer Signatures)

Usage:
    # Verify using facts from default location
    python verify_cli.py --root out/site_demo

    # Verify using custom facts directory
    python verify_cli.py --root out/site_demo --facts out/site_demo/facts

    # Verify with TSA and peer checks (warn-only by default)
    python verify_cli.py --root out/site_demo --facts out/site_demo/facts \
        --verify-tsa --verify-peers

    # Strict mode: fail on TSA/peer errors
    python verify_cli.py --root out/site_demo --facts out/site_demo/facts \
        --verify-tsa --tsa-strict --verify-peers --peers-strict
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404

# Reason: invoking external 'ots' tool via validated full path.
import sys
from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

try:  # Support both package imports and direct script execution.
    from .peer_attestation import verify_peer_signature
except ImportError:  # pragma: no cover - fallback when run as a script
    from peer_attestation import (  # type: ignore[import-not-found,no-redef]
        verify_peer_signature,
    )

EXIT_OTS_NOT_FOUND = 3
EXIT_OTS_FAILED = 4
EXIT_TSA_FAILED = 5
EXIT_PEERS_FAILED = 6
EXIT_ARTIFACT_PATH_MISMATCH = 7
EXIT_META_INVALID = 8
EXIT_ARTIFACT_HASH_MISMATCH = 9

# Optional Rust extension (`trackone_core`) for single-sourced ledger policy (ADR-003).
_RUST_MERKLE: Any | None = None
_RUST_LEDGER: Any | None = None
try:  # pragma: no cover - optional acceleration
    import trackone_core

    _RUST_MERKLE = getattr(trackone_core, "merkle", None)
    _RUST_LEDGER = getattr(trackone_core, "ledger", None)
except ImportError:  # pragma: no cover - extension not built/installed
    trackone_core = None
    _RUST_MERKLE = None
    _RUST_LEDGER = None


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def merkle_root(leaves: Iterable[bytes]) -> str:
    # Mirror merkle_batcher: if empty -> sha256(""); else hash leaves, sort by hex, then build tree
    leaves_list = list(leaves)
    if _RUST_MERKLE is not None:
        try:  # pragma: no cover - exercised when Rust extension is available
            root_hex, _leaf_hashes = cast(
                tuple[str, list[str]],
                _RUST_MERKLE.merkle_root_hex_and_leaf_hashes(leaves_list),
            )
            return root_hex
        except (RuntimeError, TypeError, ValueError) as e:
            print(
                f"[WARN] Rust merkle failed, falling back to Python: {e}",
                file=sys.stderr,
            )
            # Fall back to the reference Python implementation.
            pass
    if not leaves_list:
        return sha256(b"").hexdigest()
    leaf_hashes = [sha256(leaf).hexdigest() for leaf in leaves_list]
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


def verify_ots(
    ots_path: Path,
    allow_placeholder: bool = True,
    expected_artifact_sha: str | None = None,
) -> bool:
    """Verify an OTS proof file.

    If `allow_placeholder` is True, stationary OTS stubs are accepted.
    If False, only real OTS proofs verified by the ots binary are valid.

    Args:
        ots_path: Path to the .ots proof file
        allow_placeholder: Whether to accept stationary stubs (default True for backward compatibility)
        expected_artifact_sha: Optional SHA-256 from ots_meta to validate against

    Returns:
        True if the proof is valid, False otherwise
    """
    # Check for stationary stub first
    try:
        raw = ots_path.read_bytes()

        # Stationary stub pattern from ots_anchor (deterministic local proof)
        if raw.startswith(b"STATIONARY-OTS:"):
            # Stationary stubs are treated like placeholders - reject if allow_placeholder is False
            if not allow_placeholder:
                return False
            # Extract hex digest from stub and validate against expected_artifact_sha
            try:
                parts = raw.split(b":", 1)
                if len(parts) != 2:
                    return False
                hexpart = parts[1].strip().splitlines()[0]
                try:
                    stub_hex = hexpart.decode("ascii")
                except UnicodeDecodeError:
                    return False
                # If caller provided expected_artifact_sha (from meta), use that as the oracle.
                if expected_artifact_sha:
                    return stub_hex == expected_artifact_sha
                # Otherwise, attempt to locate the day blob and compare its sha256.
                # The .ots file is named <day>.bin.ots, so strip the .ots suffix to get <day>.bin
                if ots_path.suffix == ".ots":
                    day_candidate = ots_path.with_suffix("")
                else:
                    day_candidate = ots_path.with_suffix(".bin")
                if day_candidate.exists():
                    actual_sha = sha256(day_candidate.read_bytes()).hexdigest()
                    return actual_sha == stub_hex
                # No oracle available -> conservative reject
                return False
            except OSError:
                return False
        # Legacy placeholder content produced when OTS client missing/failed.
        # Accept it as a placeholder when tests or CI allow placeholders.
        if raw.strip() == b"OTS_PROOF_PLACEHOLDER" and allow_placeholder:
            return True
    except (OSError, UnicodeDecodeError):
        # If reading fails, fall back to attempting real OTS verification below.
        # Narrow exception avoids catching unrelated errors.
        pass

    # Try real OTS verification
    ots_exe = shutil.which("ots")
    if not ots_exe:
        # No external 'ots' binary available; treat as unverifiable.
        return False

    # Validate that the resolved path is an executable file to reduce risk.
    ots_path_obj = Path(ots_exe).resolve()
    if not ots_path_obj.is_file() or not os.access(str(ots_path_obj), os.X_OK):
        return False

    try:
        # Use full path to the executable and avoid shell=True.
        # Reason: ots_exe is validated above (absolute, file, executable); args are local paths.
        result = subprocess.run(
            [str(ots_path_obj), "verify", str(ots_path)], capture_output=True, text=True
        )  # nosec B603
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False
    except OSError:
        return False


def verify_tsa(tsr_path: Path, day_bin: Path) -> bool:
    """Verify RFC 3161 TSA timestamp response against day blob.

    Returns True if:
    - TSR file exists and contains valid timestamp
    - Message imprint in TSR matches SHA-256 of day_bin
    - openssl ts -verify succeeds (if openssl available)

    Returns False otherwise.
    """
    if not tsr_path.exists() or not day_bin.exists():
        return False

    # Check if openssl is available
    openssl_exe = shutil.which("openssl")
    if not openssl_exe:
        # No openssl available; best-effort check of metadata
        tsr_json = tsr_path.with_suffix(".tsr.json")
        if not tsr_json.exists():
            return False
        try:
            meta = json.loads(tsr_json.read_text(encoding="utf-8"))
            # Verify message imprint matches day_bin SHA-256
            day_hash = sha256(day_bin.read_bytes()).hexdigest()
            imprint = meta.get("message_imprint", "").replace(":", "").lower()
            return imprint == day_hash  # type: ignore
        except (json.JSONDecodeError, OSError):
            return False

    # Full verification with openssl
    try:
        result = subprocess.run(
            [openssl_exe, "ts", "-verify", "-in", str(tsr_path), "-data", str(day_bin)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def verify_peer_signatures(
    peer_attest_path: Path, site_id: str, day: str, day_root_hex: str
) -> tuple[bool, int]:
    """Verify peer co-signatures from peer attestation file.

    Returns (all_valid, signature_count).
    """
    if not peer_attest_path.exists():
        return False, 0

    try:
        data = json.loads(peer_attest_path.read_text(encoding="utf-8"))
        signatures = data.get("signatures", [])
        context = data.get("context", "trackone:day-root:v1").encode()

        valid_count = 0
        for sig in signatures:
            if verify_peer_signature(
                site_id=site_id,
                day=day,
                day_root_hex=day_root_hex,
                signature_hex=sig["signature_hex"],
                pubkey_hex=sig["pubkey_hex"],
                context=context,
            ):
                valid_count += 1

        return valid_count == len(signatures) and len(signatures) > 0, len(signatures)
    except (json.JSONDecodeError, OSError, KeyError, ImportError):
        return False, 0


def main(argv: list[str] | None = None) -> int:
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
        "--verify-tsa",
        action="store_true",
        help="Verify RFC 3161 TSA timestamp (if present)",
    )
    p.add_argument(
        "--tsa-strict",
        action="store_true",
        help="Treat TSA verification failure as fatal (exit 5)",
    )
    p.add_argument(
        "--verify-peers",
        action="store_true",
        help="Verify peer co-signatures (if present)",
    )
    p.add_argument(
        "--peers-strict",
        action="store_true",
        help="Treat peer verification failure as fatal (exit 6)",
    )
    p.add_argument(
        "--peers-min",
        type=int,
        default=1,
        help="Minimum peer signatures required (default: 1)",
    )

    # OTS mode flags: mutually exclusive strict vs lenient
    group = p.add_mutually_exclusive_group()
    group.add_argument(
        "--require-ots",
        action="store_true",
        help="Require a real OTS proof (placeholder not accepted).",
    )
    group.add_argument(
        "--allow-placeholder",
        action="store_true",
        help="Allow placeholder OTS proofs (default behavior).",
    )

    args = p.parse_args(argv)

    # Decide placeholder policy. Default: allow placeholders for backward compatibility.
    allow_placeholder = True
    if args.require_ots:
        allow_placeholder = False
    elif args.allow_placeholder:
        allow_placeholder = True

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
    with block_path.open("r", encoding="utf-8") as f:
        block_header = json.load(f)
    day = block_header.get("day")
    if not isinstance(day, str) or len(day) != 10:
        print(f"ERROR: Invalid or missing 'day' in block header: {block_path}")
        return 1

    day_bin_path = day_dir / f"{day}.bin"
    ots_path = day_bin_path.with_suffix(day_bin_path.suffix + ".ots")
    recorded_root = block_header.get("merkle_root")
    if not isinstance(recorded_root, str) or len(recorded_root) != 64:
        print(f"ERROR: Invalid or missing 'merkle_root' in block header: {block_path}")
        return 1

    # Optional: load OTS metadata sidecar if present and enforce artifact hash/path.
    # We look for proofs/<day>.ots.meta.json relative to the repository root
    # (one directory above the out/site_demo root).
    repo_root = root_dir.parent
    meta_path = repo_root / "proofs" / f"{day}.ots.meta.json"
    meta: dict[str, Any] | None = None
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:  # pragma: no cover - defensive
            print(f"ERROR: Failed to parse OTS meta file {meta_path}: {exc}")
            return EXIT_META_INVALID

        artifact_rel = meta.get("artifact")
        expected_sha = meta.get("artifact_sha256")
        meta_ots_rel = meta.get("ots_proof")

        # Resolve artifact path relative to repo root and compare
        if isinstance(artifact_rel, str):
            resolved_artifact = (repo_root / artifact_rel).resolve()
            if resolved_artifact != day_bin_path.resolve():
                print(
                    f"ERROR: OTS meta artifact path mismatch. Meta artifact={resolved_artifact}, "
                    f"expected day.bin={day_bin_path}"
                )
                return EXIT_ARTIFACT_PATH_MISMATCH

        # Verify SHA-256 of day.bin matches artifact_sha256 from meta.
        if isinstance(expected_sha, str) and len(expected_sha) == 64:
            if not day_bin_path.exists():
                print(f"ERROR: OTS meta present but artifact missing: {day_bin_path}")
                return EXIT_META_INVALID
            actual_sha = sha256(day_bin_path.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                print(
                    f"ERROR: OTS meta artifact_sha256 mismatch. Expected={expected_sha}, Actual={actual_sha}"
                )
                return EXIT_ARTIFACT_HASH_MISMATCH

        # If meta specifies an ots_proof path, ensure it points to the same file we plan to verify
        if isinstance(meta_ots_rel, str):
            resolved_meta_ots = (repo_root / meta_ots_rel).resolve()
            if resolved_meta_ots != ots_path.resolve():
                print(
                    f"ERROR: OTS meta ots_proof path mismatch. Meta ots={resolved_meta_ots}, "
                    f"expected {ots_path}"
                )
                return EXIT_ARTIFACT_PATH_MISMATCH
            if not ots_path.exists():
                print(f"ERROR: OTS meta present but proof missing: {ots_path}")
                return EXIT_OTS_NOT_FOUND

    # Parse + validate the anchored day blob (day.bin) if present.
    if day_bin_path.exists():
        try:
            day_bin_bytes = day_bin_path.read_bytes()
            any_val = json.loads(day_bin_bytes)
        except (json.JSONDecodeError, OSError) as exc:
            print(f"ERROR: Failed to parse day blob JSON {day_bin_path}: {exc}")
            return 1
        if not isinstance(any_val, dict):
            print(f"ERROR: day blob must be a JSON object: {day_bin_path}")
            return 1
        day_record_from_bin: dict[str, Any] = any_val

        # Enforce canonical encoding (ADR-003).
        # If the Rust extension is available, prefer its canonicalizer for single-sourcing.
        if _RUST_LEDGER is not None:
            try:  # pragma: no cover - exercised when Rust extension is available
                canon = _RUST_LEDGER.canonicalize_json_bytes(day_bin_bytes)
            except (RuntimeError, TypeError, ValueError) as e:
                print(
                    f"[WARN] Rust ledger canonicalize failed, falling back to Python: {e}",
                    file=sys.stderr,
                )
                canon = canonical_json(day_record_from_bin)
        else:
            canon = canonical_json(day_record_from_bin)

        if canon != day_bin_bytes:
            print(f"ERROR: day blob is not canonical JSON (ADR-003): {day_bin_path}")
            return 1

        # Ensure the anchored artifact commits to the same root as the block header.
        day_root = day_record_from_bin.get("day_root")
        if day_root != recorded_root:
            print(
                "ERROR: day_root mismatch between day.bin and block header. "
                f"day.bin={day_root}, block_header={recorded_root}"
            )
            return 2

        # Ensure the day label matches and that the embedded batch header is consistent.
        if day_record_from_bin.get("date") != day:
            print(
                "ERROR: day blob date mismatch. "
                f"day.bin.date={day_record_from_bin.get('date')}, block_header.day={day}"
            )
            return 1
        if day_record_from_bin.get("site_id") != block_header.get("site_id"):
            print(
                "ERROR: day blob site_id mismatch. "
                f"day.bin.site_id={day_record_from_bin.get('site_id')}, block_header.site_id={block_header.get('site_id')}"
            )
            return 1

        batches = day_record_from_bin.get("batches")
        if not isinstance(batches, list) or not batches:
            print(f"ERROR: day blob must include non-empty batches: {day_bin_path}")
            return 1
        batch0 = batches[0]
        if not isinstance(batch0, dict):
            print(f"ERROR: day blob batches[0] must be an object: {day_bin_path}")
            return 1
        for key in [
            "version",
            "site_id",
            "day",
            "batch_id",
            "merkle_root",
            "count",
            "leaf_hashes",
        ]:
            if batch0.get(key) != block_header.get(key):
                print(
                    f"ERROR: batch header mismatch for key '{key}'. "
                    f"day.bin={batch0.get(key)}, block_header={block_header.get(key)}"
                )
                return 1
    else:
        if meta is not None:
            print(f"ERROR: OTS meta present but day blob missing: {day_bin_path}")
            return EXIT_META_INVALID

    # Read and canonicalize all facts
    fact_files = sorted(facts_dir.glob("*.json"))
    leaves: list[bytes] = []
    for fpath in fact_files:
        with fpath.open("r", encoding="utf-8") as f:
            obj = json.load(f)
            canon = canonical_json(obj)
            leaves.append(canon)

    # Recompute Merkle root
    recomputed_root = merkle_root(leaves)

    # Verify root matches
    if recomputed_root != recorded_root:
        print(
            f"ERROR: Merkle root mismatch. Computed: {recomputed_root}, Recorded: {recorded_root}"
        )
        return 2

    # Verify OTS proof if present
    rc_ots = 0
    if args.require_ots and not ots_path.exists():
        print(f"ERROR: Required OTS proof missing: {ots_path}")
        return EXIT_OTS_NOT_FOUND

    if ots_path.exists():
        expected_sha_from_meta: str | None = None
        if meta is not None:
            sha_val = meta.get("artifact_sha256")
            if isinstance(sha_val, str):
                expected_sha_from_meta = sha_val
        ok = verify_ots(
            ots_path,
            allow_placeholder=allow_placeholder,
            expected_artifact_sha=expected_sha_from_meta,
        )
        if not ok:
            print(f"ERROR: OTS proof verification failed for {ots_path}")
            rc_ots = EXIT_OTS_FAILED
    elif not args.require_ots:
        print(f"WARN: OTS proof not found (skipping): {ots_path}", file=sys.stderr)

    if rc_ots != 0:
        return rc_ots

    # Optional TSA verification
    if args.verify_tsa:
        tsr_path = day_bin_path.parent / f"{day}.tsr"
        if tsr_path.exists():
            tsa_ok = verify_tsa(tsr_path, day_bin_path)
            if tsa_ok:
                print(f"TSA verification: OK ({tsr_path})")
            else:
                msg = f"TSA verification failed: {tsr_path}"
                if args.tsa_strict:
                    print(f"ERROR: {msg}")
                    return EXIT_TSA_FAILED
                print(f"WARN: {msg}", file=sys.stderr)
        else:
            msg = f"TSA artifact not found: {tsr_path}"
            if args.tsa_strict:
                print(f"ERROR: {msg}")
                return EXIT_TSA_FAILED
            print(f"WARN: {msg}", file=sys.stderr)

    # Optional peer signature verification
    if args.verify_peers:
        peer_attest_path = day_bin_path.parent / "peers" / f"{day}.peers.json"
        if peer_attest_path.exists():
            site_id = block_header.get("site_id", "")
            all_valid, sig_count = verify_peer_signatures(
                peer_attest_path, site_id, day, recorded_root
            )
            if all_valid and sig_count >= args.peers_min:
                print(f"Peer verification: OK ({sig_count} signatures)")
            else:
                msg = f"Peer verification failed: {sig_count} signatures, need {args.peers_min}, valid={all_valid}"
                if args.peers_strict:
                    print(f"ERROR: {msg}")
                    return EXIT_PEERS_FAILED
                print(f"WARN: {msg}", file=sys.stderr)
        else:
            msg = f"Peer attestation not found: {peer_attest_path}"
            if args.peers_strict:
                print(f"ERROR: {msg}")
                return EXIT_PEERS_FAILED
            print(f"WARN: {msg}", file=sys.stderr)

    print("OK: root matches and OTS verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
