#!/usr/bin/env python3
"""
merkle_batcher.py

Batch device facts into a Merkle tree and emit:
- blocks/<day>-00.block.json
- day/<day>.bin (canonical day blob for OTS)
- day/<day>.json (human-readable)
Also writes day/<day>.bin.sha256 for convenience.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path
from typing import List, Tuple

try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

DATE_RX = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def canonical_json(obj) -> bytes:
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
    leaf_hashes: List[str]  # optional aid for auditors
    ots_proof: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _h(x: bytes) -> bytes:
    return sha256(x).digest()


def merkle_root_from_leaves(leaves: List[bytes]) -> Tuple[str, List[str]]:
    """Return (root_hex, leaf_hexes) for canonicalized leaves."""
    if not leaves:
        empty = sha256(b"").hexdigest()
        return empty, []
    leaf_hashes = [sha256(leaf).hexdigest() for leaf in leaves]
    # Deterministic: sort by hash, not filename
    leaf_hashes_sorted = sorted(leaf_hashes)
    layer = [bytes.fromhex(hx) for hx in leaf_hashes_sorted]
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(_h(a + b))
        layer = nxt
    return layer[0].hex(), leaf_hashes_sorted


def load_schemas() -> dict:
    """Load fact, block_header, and day_record schemas if available."""
    schemas = {}
    schema_dir = Path(__file__).parent.parent.parent / "toolset" / "unified" / "schemas"
    for name in ["fact", "block_header", "day_record"]:
        schema_path = schema_dir / f"{name}.schema.json"
        if schema_path.exists():
            try:
                schemas[name] = json.loads(schema_path.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"[WARN] Failed to load {name} schema: {e}", file=sys.stderr)
    return schemas


def validate_against_schema(obj: dict, schema: dict, label: str) -> None:
    """Validate obj against schema; print warning if validation fails."""
    if not JSONSCHEMA_AVAILABLE:
        return
    try:
        jsonschema.validate(instance=obj, schema=schema)
        print(f"[OK] {label} validated against schema.", file=sys.stderr)
    except jsonschema.ValidationError as e:
        print(f"[WARN] {label} schema validation failed: {e.message}", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] {label} schema validation error: {e}", file=sys.stderr)


def load_facts(facts_dir: Path) -> List[bytes]:
    fact_files = sorted(facts_dir.glob("*.json"))
    leaves: List[bytes] = []
    for fpath in fact_files:
        try:
            obj = json.loads(fpath.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[ERROR] Failed to parse JSON: {fpath}: {e}", file=sys.stderr)
            raise
        leaves.append(canonical_json(obj))
    return leaves


def prev_day_root_or_zero(out_dir: Path, site: str, day: str) -> str:
    # naive previous day lookup by file presence; adjust if you want true calendar math
    # Here we scan the day/ directory for the latest *.json older than 'day'
    day_dir = out_dir / "day"
    if not day_dir.exists():
        return "00" * 32
    candidates = sorted(p for p in day_dir.glob("*.json") if p.name < f"{day}.json")
    if not candidates:
        return "00" * 32
    try:
        prev = json.loads(candidates[-1].read_text(encoding="utf-8"))
        return prev.get("day_root", "00" * 32)
    except Exception:
        return "00" * 32


def main(argv: List[str] | None = None) -> int:
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

    root_hex, leaf_hashes = merkle_root_from_leaves(leaves)
    batch_id = f"{args.site}-{args.date}-00"

    header = BlockHeader(
        version=1,
        site_id=args.site,
        day=args.date,
        batch_id=batch_id,
        merkle_root=root_hex,
        count=len(leaf_hashes),
        leaf_hashes=leaf_hashes,
        ots_proof=None,
    )

    # Write block header
    blocks_dir = args.out / "blocks"
    blocks_dir.mkdir(parents=True, exist_ok=True)
    block_path = blocks_dir / f"{args.date}-00.block.json"
    block_path.write_text(
        json.dumps(header.to_dict(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    # Day record (canonical + human-readable)
    day_dir = args.out / "day"
    day_dir.mkdir(parents=True, exist_ok=True)
    prev_root = prev_day_root_or_zero(args.out, args.site, args.date)

    day_record = {
        "version": 1,
        "site_id": args.site,
        "date": args.date,
        "prev_day_root": prev_root,
        "batches": [header.to_dict()],
        "day_root": root_hex,
    }

    # Optional schema validation
    if args.validate_schemas:
        schemas = load_schemas()
        if "block_header" in schemas:
            validate_against_schema(
                header.to_dict(), schemas["block_header"], "Block header"
            )
        if "day_record" in schemas:
            validate_against_schema(day_record, schemas["day_record"], "Day record")

    day_blob = canonical_json(day_record)
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
