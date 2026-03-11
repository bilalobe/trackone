"""
Merkle batcher integration tests.

Tests the merkle_batcher module for:
- Merkle tree reproduction and determinism
- Block and day file generation
- Schema validation
- Batch processing end-to-end
"""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Provide typing-only stubs for names injected by conftest autouse fixture
    def canonical_json(obj: Any) -> bytes:
        ...

    def merkle_root_from_leaves(leaves: Iterable[bytes]) -> tuple[str, list[str]]:
        ...

    class BlockHeader:  # pragma: no cover
        def __init__(self, *args: Any, **kwargs: Any):
            ...

        def to_dict(self) -> dict:
            ...

    def load_schemas() -> dict:
        ...

    def validate_against_schema(obj: dict, schema: dict, name: str) -> None:
        ...

    def batcher_main(args: list) -> int:
        ...


class TestMerkleReproduction:
    """Test that Merkle roots are reproducible and deterministic."""

    def test_empty_tree_reproducibility(self):
        """Empty tree should always produce sha256('') hash."""
        root1, _ = merkle_root_from_leaves([])
        root2, _ = merkle_root_from_leaves([])
        expected = sha256(b"").hexdigest()

        assert root1 == expected
        assert root2 == expected
        assert root1 == root2

    def test_single_fact_reproducibility(self):
        """Single fact should always produce the same root."""
        fact = {
            "pod_id": "0000000000000001",
            "fc": 1,
            "ingest_time": 1759752000,
            "ingest_time_rfc3339_utc": "2025-10-06T12:00:00Z",
            "pod_time": None,
            "kind": "Custom",
            "payload": {"temp": 22.5},
        }

        leaf = canonical_json(fact)
        root1, hashes1 = merkle_root_from_leaves([leaf])
        root2, hashes2 = merkle_root_from_leaves([leaf])

        assert root1 == root2
        assert hashes1 == hashes2
        assert root1 == sha256(leaf).hexdigest()

    def test_multiple_facts_reproducibility(self):
        """Multiple facts should produce consistent roots."""
        facts = [
            {
                "pod_id": "0000000000000001",
                "fc": 1,
                "ingest_time": 1759744800,
                "ingest_time_rfc3339_utc": "2025-10-06T10:00:00Z",
                "pod_time": None,
                "kind": "Custom",
                "payload": {"x": 1},
            },
            {
                "pod_id": "0000000000000002",
                "fc": 2,
                "ingest_time": 1759748400,
                "ingest_time_rfc3339_utc": "2025-10-06T11:00:00Z",
                "pod_time": None,
                "kind": "Custom",
                "payload": {"x": 2},
            },
        ]

        leaves = [canonical_json(f) for f in facts]
        root1, hashes1 = merkle_root_from_leaves(leaves)
        root2, hashes2 = merkle_root_from_leaves(leaves)

        assert root1 == root2
        assert hashes1 == hashes2
