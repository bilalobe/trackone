#!/usr/bin/env python3
"""Generate the published canonical CBOR commitment corpus."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.gateway.canonical_cbor import canonicalize_obj_to_cbor_native  # noqa: E402
from scripts.gateway.merkle_batcher import merkle_root_from_leaves  # noqa: E402
from trackone_core.ledger import sha256_hex  # noqa: E402

OUT_DIR = ROOT / "toolset" / "vectors" / "trackone-canonical-cbor-v1"
FACTS_DIR = OUT_DIR / "facts"
PROFILE_ID = "trackone-canonical-cbor-v1"
CDDL_PROFILE = "toolset/unified/cddl/commitment-artifacts-v1.cddl"
MANIFEST_SCHEMA = "toolset/unified/schemas/commitment_vector_manifest.schema.json"
SITE_ID = "an-001"
DATE = "2025-10-07"
BATCH_ID = f"{SITE_ID}-{DATE}-00"
PREV_DAY_ROOT = "00" * 32
CBOR_PROFILE = {
    "id": "trackone-deterministic-json-cbor-v1",
    "map_key_order": "encoded-key-length-then-utf8-bytes",
    "integer_encoding": "shortest-form",
    "float_encoding": "shortest-exact-float16-float32-float64",
    "non_finite_floats": "invalid",
}
MERKLE_POLICY = {
    "id": "trackone-adr003-sha256-hash-sorted-v1",
    "leaf_hash": "SHA-256(leaf_cbor_bytes)",
    "leaf_order": "lexicographic-raw-32-byte-hash",
    "parent_hash": "SHA-256(left || right)",
    "odd_leaf": "duplicate-last",
    "empty_root": sha256_hex(b""),
}

FACTS: list[dict[str, Any]] = [
    {
        "pod_id": "pod-001",
        "fc": 1,
        "ingest_time": "2025-10-07T00:00:01Z",
        "pod_time": "2025-10-07T00:00:00Z",
        "kind": "env.sample",
        "payload": {"temperature_c": 1.0, "humidity_pct": 45},
    },
    {
        "pod_id": "pod-001",
        "fc": 2,
        "ingest_time": "2025-10-07T00:05:01Z",
        "pod_time": "2025-10-07T00:05:00Z",
        "kind": "env.sample",
        "payload": {"temperature_c": 1.5, "humidity_pct": 46},
    },
    {
        "pod_id": "pod-001",
        "fc": 3,
        "ingest_time": "2025-10-07T00:10:01Z",
        "pod_time": "2025-10-07T00:10:00Z",
        "kind": "power.sample",
        "payload": {"energy_uj": 100000.0, "battery_mv": 3300},
    },
]


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    FACTS_DIR.mkdir(parents=True, exist_ok=True)

    fact_entries: list[dict[str, Any]] = []
    leaves: list[bytes] = []
    for index, fact in enumerate(FACTS, start=1):
        stem = f"fact-{index:03d}"
        json_path = FACTS_DIR / f"{stem}.json"
        cbor_path = FACTS_DIR / f"{stem}.cbor"
        cbor_bytes = canonicalize_obj_to_cbor_native(fact)
        leaves.append(cbor_bytes)
        _write_json(json_path, fact)
        cbor_path.write_bytes(cbor_bytes)
        fact_entries.append(
            {
                "name": stem,
                "json_path": str(json_path.relative_to(OUT_DIR)),
                "cbor_path": str(cbor_path.relative_to(OUT_DIR)),
                "cbor_sha256": sha256_hex(cbor_bytes),
            }
        )

    merkle_root, leaf_hashes = merkle_root_from_leaves(leaves)
    block_header = {
        "version": 1,
        "site_id": SITE_ID,
        "day": DATE,
        "batch_id": BATCH_ID,
        "merkle_root": merkle_root,
        "count": len(leaves),
        "leaf_hashes": leaf_hashes,
    }
    day_record = {
        "version": 1,
        "site_id": SITE_ID,
        "date": DATE,
        "prev_day_root": PREV_DAY_ROOT,
        "batches": [block_header],
        "day_root": merkle_root,
    }
    day_cbor = canonicalize_obj_to_cbor_native(day_record)

    _write_json(OUT_DIR / "block-header.json", block_header)
    _write_json(OUT_DIR / "day-record.json", day_record)
    (OUT_DIR / "day-record.cbor").write_bytes(day_cbor)

    manifest = {
        "version": 1,
        "commitment_profile_id": PROFILE_ID,
        "cddl_profile": CDDL_PROFILE,
        "manifest_schema": MANIFEST_SCHEMA,
        "fact_cbor_shape": "fact-json-projection-v1",
        "day_record_cbor_shape": "day-record-v1",
        "cbor_profile": CBOR_PROFILE,
        "merkle_policy": MERKLE_POLICY,
        "site_id": SITE_ID,
        "date": DATE,
        "prev_day_root": PREV_DAY_ROOT,
        "batch_id": BATCH_ID,
        "facts": fact_entries,
        "block_header_path": "block-header.json",
        "day_record_json_path": "day-record.json",
        "day_record_cbor_path": "day-record.cbor",
        "leaf_hashes": leaf_hashes,
        "merkle_root": merkle_root,
        "day_cbor_sha256": sha256_hex(day_cbor),
    }
    _write_json(OUT_DIR / "manifest.json", manifest)
    print(f"Wrote canonical commitment vectors to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
