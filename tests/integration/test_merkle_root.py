#!/usr/bin/env python3
"""
Merkle root tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations

from hashlib import sha256


class TestMerkleRoot:
    def test_empty_leaves(self):
        root, hashes = merkle_root_from_leaves([])
        assert root == sha256(b"").hexdigest()
        assert hashes == []

    def test_single_leaf(self):
        leaf = b"test_data"
        root, hashes = merkle_root_from_leaves([leaf])
        expected = sha256(leaf).hexdigest()
        assert root == expected
        assert len(hashes) == 1

    def test_two_leaves(self):
        leaf1 = b"data1"
        leaf2 = b"data2"
        root, hashes = merkle_root_from_leaves([leaf1, leaf2])

        # Compute expected: hash leaves, sort, then combine
        h1 = sha256(leaf1).hexdigest()
        h2 = sha256(leaf2).hexdigest()
        sorted_hashes = sorted([h1, h2])
        combined = bytes.fromhex(sorted_hashes[0]) + bytes.fromhex(sorted_hashes[1])
        expected = sha256(combined).hexdigest()

        assert root == expected
        assert set(hashes) == {h1, h2}

    def test_deterministic_regardless_of_input_order(self):
        leaf1 = b"alpha"
        leaf2 = b"beta"
        leaf3 = b"gamma"

        root1, _ = merkle_root_from_leaves([leaf1, leaf2, leaf3])
        root2, _ = merkle_root_from_leaves([leaf3, leaf1, leaf2])
        root3, _ = merkle_root_from_leaves([leaf2, leaf3, leaf1])

        assert root1 == root2 == root3

    def test_odd_number_of_leaves(self):
        # Three leaves: should duplicate the last one when building tree
        leaves = [b"a", b"b", b"c"]
        root, hashes = merkle_root_from_leaves(leaves)
        assert len(hashes) == 3
        assert len(root) == 64  # hex sha256
