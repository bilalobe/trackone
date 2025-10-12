#!/usr/bin/env python3
"""
test_merkle_repro.py

Tests for Merkle tree reproduction and determinism.
Verifies that the same facts always produce the same Merkle root.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "gateway"))

from hashlib import sha256

import pytest
from merkle_batcher import canonical_json, merkle_root_from_leaves


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
            "device_id": "pod-test",
            "timestamp": "2025-10-06T12:00:00Z",
            "nonce": "a1b2c3d4e5f6",
            "payload": {"temp": 22.5},
        }

        leaf = canonical_json(fact)
        root1, hashes1 = merkle_root_from_leaves([leaf])
        root2, hashes2 = merkle_root_from_leaves([leaf])

        assert root1 == root2
        assert hashes1 == hashes2
        assert root1 == sha256(leaf).hexdigest()

    def test_multiple_facts_reproducibility(self):
        """Multiple facts should always produce the same root regardless of input order."""
        facts = [
            {
                "device_id": "pod-01",
                "timestamp": "2025-10-06T10:00:00Z",
                "nonce": "aaa",
                "payload": {"x": 1},
            },
            {
                "device_id": "pod-02",
                "timestamp": "2025-10-06T10:01:00Z",
                "nonce": "bbb",
                "payload": {"x": 2},
            },
            {
                "device_id": "pod-03",
                "timestamp": "2025-10-06T10:02:00Z",
                "nonce": "ccc",
                "payload": {"x": 3},
            },
        ]

        leaves = [canonical_json(f) for f in facts]

        # Compute root multiple times with different input orders
        root1, hashes1 = merkle_root_from_leaves(leaves)
        root2, hashes2 = merkle_root_from_leaves(leaves[::-1])  # reversed
        root3, hashes3 = merkle_root_from_leaves(
            [leaves[1], leaves[0], leaves[2]]
        )  # shuffled

        assert root1 == root2 == root3
        assert sorted(hashes1) == sorted(hashes2) == sorted(hashes3)

    def test_canonical_json_reproducibility(self):
        """Canonical JSON should be deterministic."""
        obj = {
            "z": "last",
            "a": "first",
            "nested": {"y": 2, "x": 1},
            "array": [3, 2, 1],
        }

        result1 = canonical_json(obj)
        result2 = canonical_json(obj)

        assert result1 == result2
        # Verify keys are sorted
        assert result1.startswith(b'{"a":')

    def test_known_merkle_root_vector(self):
        """Test against a known Merkle root computation."""
        # Simple known case: two leaves "a" and "b"
        leaf_a = b"a"
        leaf_b = b"b"

        # Compute expected manually
        hash_a = sha256(leaf_a).hexdigest()
        hash_b = sha256(leaf_b).hexdigest()
        sorted_hashes = sorted([hash_a, hash_b])
        combined = bytes.fromhex(sorted_hashes[0]) + bytes.fromhex(sorted_hashes[1])
        expected_root = sha256(combined).hexdigest()

        root, hashes = merkle_root_from_leaves([leaf_a, leaf_b])

        assert root == expected_root
        assert sorted(hashes) == sorted_hashes

    def test_merkle_root_changes_with_different_data(self):
        """Different facts should produce different Merkle roots."""
        fact1 = {
            "device_id": "pod-01",
            "timestamp": "2025-10-06T10:00:00Z",
            "nonce": "aaa",
            "payload": {"x": 1},
        }
        fact2 = {
            "device_id": "pod-02",
            "timestamp": "2025-10-06T10:00:00Z",
            "nonce": "aaa",
            "payload": {"x": 2},
        }

        leaf1 = canonical_json(fact1)
        leaf2 = canonical_json(fact2)

        root1, _ = merkle_root_from_leaves([leaf1])
        root2, _ = merkle_root_from_leaves([leaf2])

        assert root1 != root2

    def test_merkle_root_power_of_two_leaves(self):
        """Test Merkle root with power-of-2 number of leaves (no duplication needed)."""
        leaves = [b"leaf1", b"leaf2", b"leaf3", b"leaf4"]
        root, hashes = merkle_root_from_leaves(leaves)

        assert len(hashes) == 4
        assert len(root) == 64  # hex sha256

        # Verify reproducibility
        root2, _ = merkle_root_from_leaves(leaves)
        assert root == root2

    def test_merkle_root_non_power_of_two_leaves(self):
        """Test Merkle root with non-power-of-2 leaves (requires duplication)."""
        leaves = [b"leaf1", b"leaf2", b"leaf3"]
        root, hashes = merkle_root_from_leaves(leaves)

        assert len(hashes) == 3
        assert len(root) == 64

        # Verify reproducibility
        root2, _ = merkle_root_from_leaves(leaves)
        assert root == root2


class TestCanonicalJsonEdgeCases:
    """Test edge cases for canonical JSON serialization."""

    def test_unicode_handling(self):
        """Unicode characters should be properly encoded."""
        obj = {"message": "Hello 世界", "emoji": "🎉"}
        result = canonical_json(obj)

        # Should be UTF-8 encoded
        assert isinstance(result, bytes)
        # Should be reproducible
        assert result == canonical_json(obj)

    def test_numeric_precision(self):
        """Numeric values should maintain precision."""
        obj = {"float": 3.14159265359, "int": 42, "negative": -100.5}
        result = canonical_json(obj)

        # Verify reproducibility
        assert result == canonical_json(obj)

    def test_nested_structures(self):
        """Deeply nested structures should be canonicalized correctly."""
        obj = {
            "level1": {
                "z": "last",
                "a": "first",
                "level2": {"nested": [3, 2, 1], "deep": {"z": 26, "a": 1}},
            }
        }

        result = canonical_json(obj)
        # Keys should be sorted at all levels
        result_str = result.decode("utf-8")
        assert result_str.startswith('{"level1":{"a":')

    def test_boolean_and_null(self):
        """Boolean and null values should serialize correctly."""
        obj = {"bool_true": True, "bool_false": False, "null_val": None}
        result = canonical_json(obj)

        result_str = result.decode("utf-8")
        assert '"bool_false":false' in result_str
        assert '"bool_true":true' in result_str
        assert '"null_val":null' in result_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
