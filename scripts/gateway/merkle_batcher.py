#!/usr/bin/env python3
"""
merkle_batcher.py

Batch device facts into a Merkle tree and emit deterministic artifacts.

This script implements the core batching logic for Track1 telemetry, producing:
- blocks/<day>-00.block.json — signed-ready block header with merkle_root
- day/<day>.cbor — canonical day artifact (for OpenTimestamps anchoring)
- day/<day>.json — human-readable day record
- day/<day>.cbor.sha256 — SHA-256 hash (for convenience)

Audit artifacts (for example `audit/rejections-<day>.ndjson`) are not part of the
ledger input and are never consumed when building Merkle commitments.

Determinism guarantees (ADR-003):
1. Deterministic CBOR commitment bytes for fact/day artifacts
2. Hash-sorted Merkle leaves: sorts leaf hashes before building tree (order-independent)
3. Day chaining: includes prev_day_root (32 zero bytes for genesis day)
4. Reproducible across runs: same facts/ → identical merkle_root and day.cbor SHA-256

References:
- ADR-003: Canonicalization, Merkle Policy, Daily OTS Anchoring

Usage:
    python merkle_batcher.py \\
        --facts out/site_demo/facts \\
        --out out/site_demo \\
        --site an-001 \\
        --date 2025-10-07 \\
        --validate-schemas
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import trackone_core.ledger as ledger
import trackone_core.merkle as merkle

try:  # Support both package imports and direct script execution.
    from .schema_validation import (
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        validate_instance_if_available,
    )
except ImportError:  # pragma: no cover - fallback when run as a script
    from schema_validation import (  # type: ignore
        SCHEMA_VALIDATION_EXCEPTIONS,
        load_schema,
        validate_instance_if_available,
    )

DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def canonical_json(obj: Any) -> bytes:
    """Canonicalize JSON: sorted keys, UTF-8, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class BlockHeader:
    version: int
    site_id: str
    day: str
    batch_id: str
    merkle_root: str  # hex sha256
    count: int
    leaf_hashes: list[str]  # optional aid for auditors

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def _h(x: bytes) -> bytes:
    return sha256(x).digest()


def merkle_root_from_leaves(leaves: list[bytes]) -> tuple[str, list[str]]:
    """Return (root_hex, leaf_hexes) for canonicalized leaves."""
    try:  # pragma: no cover - exercised when Rust extension is available
        return cast(
            tuple[str, list[str]],
            merkle.merkle_root_hex_and_leaf_hashes(leaves),
        )
    except (AttributeError, ImportError) as exc:
        raise RuntimeError(
            "trackone_core native merkle helper is required for authoritative "
            "commitment paths. Build/install the native extension or run via tox."
        ) from exc
    except (RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "trackone_core native merkle helper failed during authoritative "
            "Merkle computation"
        ) from exc


def load_schemas() -> dict[str, Any]:
    """Load fact, block_header, and day_record schemas if available."""
    schemas: dict[str, Any] = {}
    for name in ["fact", "block_header", "day_record", "ots_meta", "peer_attest"]:
        schema = load_schema(name)
        if schema is not None:
            schemas[name] = schema
    return schemas


def validate_against_schema(
    obj: dict[str, Any], schema: dict[str, Any], label: str
) -> None:
    """Validate obj against schema; print warning if validation fails."""
    if not schema:
        return
    try:
        validated = validate_instance_if_available(obj, schema)
        if not validated:
            print(
                f"[WARN] jsonschema unavailable; {label} schema validation skipped.",
                file=sys.stderr,
            )
            return
        print(f"[OK] {label} validated against schema.", file=sys.stderr)
    except SCHEMA_VALIDATION_EXCEPTIONS as e:
        print(f"[WARN] {label} schema validation failure: {e}", file=sys.stderr)


def load_facts(facts_dir: Path) -> list[bytes]:
    """Load only canonical fact commitments from `facts_dir`.

    Sibling audit evidence directories are intentionally ignored and must not
    influence Merkle roots.
    """
    fact_files = sorted(facts_dir.glob("*.cbor"))
    if not fact_files:
        json_candidates = sorted(facts_dir.glob("*.json"))
        if json_candidates:
            # During migration, legacy JSON facts may exist without CBOR equivalents.
            # Emit a clear CLI error and return an empty list so callers can fail gracefully
            # instead of surfacing an unhandled ValueError.
            print(
                "[ERROR] JSON facts found but CBOR facts are required for "
                "commitments (ADR-039). Please regenerate facts as CBOR.",
                file=sys.stderr,
            )
            return []
    leaves: list[bytes] = []
    for fpath in fact_files:
        try:
            leaves.append(fpath.read_bytes())
        except OSError as e:
            print(f"[ERROR] Failed to read CBOR fact: {fpath}: {e}", file=sys.stderr)
            raise
    return leaves


def prev_day_root_or_zero(
    out_dir: Path, site_or_day: str, day: str | None = None
) -> str:
    """Return the previous day's root or zeros.

    Accepts either:
      prev_day_root_or_zero(out_dir, day)
    or
      prev_day_root_or_zero(out_dir, site, day)

    When `site` is provided, only prior day records for that site are eligible
    to satisfy the chain linkage.
    """
    # Determine parameters depending on call style.
    site_val: str | None
    day_val: str
    if day is None:
        site_val = None
        day_val = site_or_day
    else:
        site_val = site_or_day
        day_val = day

    # Scan day/ for the latest prior JSON record older than `day_val`. When
    # site linkage is requested, skip unrelated sites but fail closed if the
    # selected same-site record is unreadable or malformed.
    day_dir = out_dir / "day"
    if not day_dir.exists():
        return "00" * 32
    candidates = sorted(
        (p for p in day_dir.glob("*.json") if p.name < f"{day_val}.json"),
        reverse=True,
    )
    if not candidates:
        return "00" * 32
    for candidate in candidates:
        try:
            prev_any = json.loads(candidate.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return "00" * 32
        if not isinstance(prev_any, dict):
            return "00" * 32
        if site_val is not None:
            candidate_site = prev_any.get("site_id")
            if not isinstance(candidate_site, str):
                return "00" * 32
            if candidate_site != site_val:
                continue
        val = prev_any.get("day_root")
        if isinstance(val, str):
            return val
        return "00" * 32
    return "00" * 32


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Batch facts into Merkle root; emit block header and canonical day artifact."
    )
    ap.add_argument(
        "--facts", type=Path, required=True, help="Directory containing fact CBOR files"
    )
    ap.add_argument(
        "--out", type=Path, required=True, help="Output directory (e.g. out/site_demo)"
    )
    ap.add_argument("--site", type=str, required=True, help="Site identifier")
    ap.add_argument("--date", type=str, required=True, help="UTC day label YYYY-MM-DD")
    ap.add_argument(
        "--allow-empty",
        action="store_true",
        help="Allow empty fact set (root = sha256(''))",
    )
    ap.add_argument(
        "--validate-schemas",
        action="store_true",
        help="Validate outputs against JSON schemas",
    )
    args = ap.parse_args(argv)

    if not DATE_RX.match(args.date):
        print(f"[ERROR] --date must be YYYY-MM-DD, got {args.date}", file=sys.stderr)
        return 2

    leaves = load_facts(args.facts)
    if not leaves and not args.allow_empty:
        print(
            "[ERROR] No facts found. Use --allow-empty if intentional.", file=sys.stderr
        )
        return 1

    batch_id = f"{args.site}-{args.date}-00"
    prev_root = prev_day_root_or_zero(args.out, args.site, args.date)

    header_dict: dict[str, Any] | None = None
    header_json_bytes: bytes | None = None
    day_record: dict[str, Any] | None = None
    day_blob: bytes | None = None
    root_hex: str | None = None

    try:  # pragma: no cover - exercised when Rust extension is available
        (
            header_json_bytes,
            day_blob,
            day_json_bytes,
        ) = ledger.build_day_v1_single_batch_cbor(
            args.site, args.date, prev_root, batch_id, leaves
        )
        header_dict = json.loads(header_json_bytes)
        day_record = json.loads(day_json_bytes)
        root_hex = header_dict.get("merkle_root")
    except (AttributeError, ImportError):
        print(
            "[ERROR] trackone_core native ledger helper is required for "
            "authoritative commitment paths. Build/install the native extension "
            "or run via tox.",
            file=sys.stderr,
        )
        return 1
    except (
        RuntimeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    # Type narrowing: after the fallback block, these must be non-None
    assert header_dict is not None
    assert day_record is not None
    assert day_blob is not None

    # Write block header
    blocks_dir = args.out / "blocks"
    blocks_dir.mkdir(parents=True, exist_ok=True)
    block_path = blocks_dir / f"{args.date}-00.block.json"

    # Day record (canonical + human-readable)
    day_dir = args.out / "day"
    day_dir.mkdir(parents=True, exist_ok=True)

    # Optional schema validation
    if args.validate_schemas:
        schemas = load_schemas()
        if "block_header" in schemas:
            validate_against_schema(
                header_dict, schemas["block_header"], "Block header"
            )
        if "day_record" in schemas:
            validate_against_schema(day_record, schemas["day_record"], "Day record")

    # Persist canonical artifacts.
    if header_json_bytes is not None:
        block_path.write_bytes(header_json_bytes + b"\n")
    else:
        block_path.write_text(
            json.dumps(header_dict, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    day_cbor_path = day_dir / f"{args.date}.cbor"
    day_cbor_path.write_bytes(day_blob)

    # Convenience sha256 file
    sha_path = day_dir / f"{args.date}.cbor.sha256"
    sha_path.write_text(sha256(day_blob).hexdigest() + "\n", encoding="utf-8")

    # Human-readable
    day_json_path = day_dir / f"{args.date}.json"
    day_json_path.write_text(json.dumps(day_record, indent=2) + "\n", encoding="utf-8")

    print(f"[OK] Merkle root: {root_hex}")
    print(f"[OK] Block header: {block_path}")
    print(f"[OK] Day artifact: {day_cbor_path}")
    print(f"[OK] Day record: {day_json_path}")
    print(f"[OK] SHA256(day.cbor): {sha_path.read_text().strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
