from __future__ import annotations

import json
import secrets
from typing import Any

import pytest

from scripts.gateway.merkle_batcher import canonical_json, merkle_root_from_leaves


def _make_leaf(i: int) -> bytes:
    # Deterministic-ish content size; randomness is fine for benchmarking
    obj = {
        "id": i,
        "device": f"pod-{i % 1000:03d}",
        "ts": 1730000000 + i,
        "payload": {
            "counter": i,
            "temp_c": (i % 2000 - 1000) / 100.0,
            "bioimpedance": (i % 500) / 100.0,
            "rand": secrets.token_hex(16),
        },
    }
    return canonical_json(obj)


@pytest.mark.parametrize("n", [16, 256, 2048])
def test_merkle_root_scale(benchmark, n: int):
    """Build a Merkle root over N canonicalized leaves."""
    leaves = [_make_leaf(i) for i in range(n)]

    def fn() -> tuple[str, list[str]]:
        return merkle_root_from_leaves(leaves)

    root_hex, leaf_hexes = benchmark(fn)
    assert isinstance(root_hex, str) and len(root_hex) == 64
    assert isinstance(leaf_hexes, list) and len(leaf_hexes) == n


def test_canonical_json_medium_obj(benchmark):
    """Canonicalize a moderately nested JSON object."""
    obj: dict[str, Any] = {
        "version": 1,
        "site_id": "an-001",
        "date": "2025-10-07",
        "batches": [
            {
                "batch_id": "an-001-2025-10-07-00",
                "count": 128,
                "leaf_hashes": [secrets.token_hex(32) for _ in range(32)],
                "merkle_root": secrets.token_hex(32),
            }
        ],
        "meta": {f"k{i}": i for i in range(200)},
    }

    def fn() -> bytes:
        return canonical_json(obj)

    out = benchmark(fn)
    # Confirm JSON round-trips and is bytes
    assert isinstance(out, bytes)
    parsed = json.loads(out.decode("utf-8"))
    assert parsed.get("version") == 1
