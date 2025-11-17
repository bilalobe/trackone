#!/usr/bin/env python3
"""
Merkle root edge case tests (moved from test_edge_cases.py)
"""
from __future__ import annotations


class TestMerkleRootEdgeCases:
    """Test Merkle root computation edge cases."""

    def test_merkle_root_single_byte_leaves(self, merkle_batcher):
        """Test with minimal single-byte leaves."""
        leaves = [b"a", b"b", b"c", b"d"]
        root, hashes = merkle_batcher.merkle_root_from_leaves(leaves)

        assert isinstance(root, str)
        assert len(root) == 64
        assert len(hashes) == 4

    def test_merkle_root_large_number_of_leaves(self, merkle_batcher):
        """Test with many leaves."""
        leaves = [f"leaf{i}".encode() for i in range(100)]
        root, hashes = merkle_batcher.merkle_root_from_leaves(leaves)

        assert isinstance(root, str)
        assert len(root) == 64
        assert len(hashes) == 100

    def test_merkle_root_duplicate_leaves(self, merkle_batcher):
        """Test with duplicate leaves."""
        leaves = [b"same", b"same", b"same"]
        root1, hashes1 = merkle_batcher.merkle_root_from_leaves(leaves)

        # All hashes should be identical
        assert len(set(hashes1)) == 1

        # But root should still be computed
        assert isinstance(root1, str)
        assert len(root1) == 64

    def test_merkle_root_binary_data(self, merkle_batcher):
        """Test with arbitrary binary data."""
        leaves = [bytes([i] * 32) for i in range(5)]
        root, hashes = merkle_batcher.merkle_root_from_leaves(leaves)

        assert isinstance(root, str)
        assert len(root) == 64
        assert len(hashes) == 5
