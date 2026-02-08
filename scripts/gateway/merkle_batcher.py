#!/usr/bin/env python3
"""
merkle_batcher.py

Batch device facts into a Merkle tree and emit deterministic artifacts.

This script implements the core batching logic for Track1 telemetry, producing:
- blocks/<day>-00.block.json — signed-ready block header with merkle_root
- day/<day>.bin — canonical day blob (for OpenTimestamps anchoring)
- day/<day>.json — human-readable day record
- day/<day>.bin.sha256 — SHA-256 hash (for convenience)

Determinism guarantees (ADR-003):
1. Canonical JSON: sorted keys, UTF-8, no whitespace via json.dumps(sort_keys=True)
2. Hash-sorted Merkle leaves: sorts leaf hashes before building tree (order-independent)
3. Day chaining: includes prev_day_root (32 zero bytes for genesis day)
4. Reproducible across runs: same facts/ → identical merkle_root and day.bin SHA-256

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

jsonschema: Any | None
try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    jsonschema = None
    JSONSCHEMA_AVAILABLE = False

DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")

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
    if _RUST_MERKLE is not None:
        try:  # pragma: no cover - exercised when Rust extension is available
            return cast(
                tuple[str, list[str]],
                _RUST_MERKLE.merkle_root_hex_and_leaf_hashes(leaves),
            )
        except (RuntimeError, TypeError, ValueError) as e:
            print(
                f"[WARN] Rust merkle failed, falling back to Python: {e}",
                file=sys.stderr,
            )
            # Fall back to the reference Python implementation.
            pass
    if not leaves:
        empty = sha256(b"").hexdigest()
        return empty, []
    leaf_hashes = [sha256(leaf).hexdigest() for leaf in leaves]
    # Deterministic: sort by hash, not filename
    leaf_hashes_sorted = sorted(leaf_hashes)
    layer = [bytes.fromhex(hx) for hx in leaf_hashes_sorted]
    while len(layer) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(_h(a + b))
        layer = nxt
    return layer[0].hex(), leaf_hashes_sorted


def load_schemas() -> dict[str, Any]:
    """Load fact, block_header, and day_record schemas if available."""
    schemas: dict[str, Any] = {}
    schema_dir = Path(__file__).parent.parent.parent / "toolset" / "unified" / "schemas"
    for name in ["fact", "block_header", "day_record", "ots_meta"]:
        schema_path = schema_dir / f"{name}.schema.json"
        if schema_path.exists():
            try:
                schemas[name] = json.loads(schema_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                print(f"[WARN] Failed to load {name} schema: {e}", file=sys.stderr)
    return schemas


def validate_against_schema(
    obj: dict[str, Any], schema: dict[str, Any], label: str
) -> None:
    """Validate obj against schema; print warning if validation fails."""
    if not JSONSCHEMA_AVAILABLE or jsonschema is None:
        return
    try:
        # Type narrowing: jsonschema is not None here due to the guard above
        assert jsonschema is not None  # nosec B101 - type narrowing for mypy
        jsonschema.validate(instance=obj, schema=schema)
        print(f"[OK] {label} validated against schema.", file=sys.stderr)
    except (jsonschema.ValidationError, jsonschema.SchemaError) as e:
        print(f"[WARN] {label} schema validation failure: {e}", file=sys.stderr)
    except jsonschema.RefResolutionError as e:
        print(
            f"[WARN] {label} schema reference resolution failure: {e}", file=sys.stderr
        )


def load_facts(facts_dir: Path) -> list[bytes]:
    fact_files = sorted(facts_dir.glob("*.json"))
    leaves: list[bytes] = []
    for fpath in fact_files:
        try:
            obj = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            print(f"[ERROR] Failed to parse JSON: {fpath}: {e}", file=sys.stderr)
            raise
        leaves.append(canonical_json(obj))
    return leaves


def prev_day_root_or_zero(
    out_dir: Path, site_or_day: str, day: str | None = None
) -> str:
    """Return the previous day's root or zeros.

    Accepts either:
      prev_day_root_or_zero(out_dir, day)
    or
      prev_day_root_or_zero(out_dir, site, day)

    The `site` argument is currently unused but accepted for backward/forward compatibility.
    """
    # Determine day parameter depending on call style
    day_val = site_or_day if day is None else day

    # naive previous day lookup by file presence; adjust if you want true calendar math
    # Here we scan the day/ directory for the latest *.json older than 'day'
    day_dir = out_dir / "day"
    if not day_dir.exists():
        return "00" * 32
    candidates = sorted(p for p in day_dir.glob("*.json") if p.name < f"{day_val}.json")
    if not candidates:
        return "00" * 32
    try:
        prev_any = json.loads(candidates[-1].read_text(encoding="utf-8"))
        if isinstance(prev_any, dict):
            val = prev_any.get("day_root")
            if isinstance(val, str):
                return val
        return "00" * 32
    except (json.JSONDecodeError, OSError):
        return "00" * 32


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Batch facts into Merkle root; emit block header and canonical day blob."
    )
    ap.add_argument(
        "--facts", type=Path, required=True, help="Directory containing fact JSON files"
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

    # Prefer single-sourced stamping via Rust ledger helpers when available.
    header_dict: dict[str, Any] | None = None
    header_json_bytes: bytes | None = None
    day_record: dict[str, Any] | None = None
    day_blob: bytes | None = None
    root_hex: str | None = None
    leaf_hashes: list[str] | None = None

    if _RUST_LEDGER is not None:
        try:  # pragma: no cover - exercised when Rust extension is available
            header_json_bytes, day_blob = _RUST_LEDGER.build_day_v1_single_batch(
                args.site, args.date, prev_root, batch_id, leaves
            )
            header_dict = json.loads(header_json_bytes)
            day_record = json.loads(day_blob)
            root_hex = header_dict.get("merkle_root")
            leaf_hashes = header_dict.get("leaf_hashes")
        except (RuntimeError, TypeError, ValueError, json.JSONDecodeError) as e:
            print(
                f"[WARN] Rust ledger failed, falling back to Python: {e}",
                file=sys.stderr,
            )
            header_dict = None
            header_json_bytes = None
            day_record = None
            day_blob = None
            root_hex = None
            leaf_hashes = None

    if header_dict is None or day_record is None or day_blob is None:
        root_hex, leaf_hashes = merkle_root_from_leaves(leaves)
        header = BlockHeader(
            version=1,
            site_id=args.site,
            day=args.date,
            batch_id=batch_id,
            merkle_root=root_hex,
            count=len(leaf_hashes),
            leaf_hashes=leaf_hashes,
        )
        header_dict = header.to_dict()
        day_record = {
            "version": 1,
            "site_id": args.site,
            "date": args.date,
            "prev_day_root": prev_root,
            "batches": [header_dict],
            "day_root": root_hex,
        }
        day_blob = canonical_json(day_record)

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

    day_bin_path = day_dir / f"{args.date}.bin"
    day_bin_path.write_bytes(day_blob)

    # Convenience sha256 file
    sha_path = day_dir / f"{args.date}.bin.sha256"
    sha_path.write_text(sha256(day_blob).hexdigest() + "\n", encoding="utf-8")

    # Human-readable
    day_json_path = day_dir / f"{args.date}.json"
    day_json_path.write_text(json.dumps(day_record, indent=2) + "\n", encoding="utf-8")

    print(f"[OK] Merkle root: {root_hex}")
    print(f"[OK] Block header: {block_path}")
    print(f"[OK] Day blob: {day_bin_path}")
    print(f"[OK] Day record: {day_json_path}")
    print(f"[OK] SHA256(day.bin): {sha_path.read_text().strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
