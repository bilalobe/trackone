#!/usr/bin/env python3
"""
BlockHeader edge case tests (moved from test_edge_cases.py)
"""
from __future__ import annotations

import json


class TestBlockHeader:
    """Test BlockHeader functionality."""

    def test_block_header_with_none_ots_proof(self, merkle_batcher):
        header = merkle_batcher.BlockHeader(
            version=1,
            site_id="test",
            day="2025-10-07",
            batch_id="test-2025-10-07-00",
            merkle_root="a" * 64,
            count=0,
            leaf_hashes=[],
            ots_proof=None,
        )

        d = header.to_dict()
        assert d["ots_proof"] is None

    def test_block_header_with_ots_proof(self, merkle_batcher):
        header = merkle_batcher.BlockHeader(
            version=1,
            site_id="test",
            day="2025-10-07",
            batch_id="test-2025-10-07-00",
            merkle_root="a" * 64,
            count=1,
            leaf_hashes=["b" * 64],
            ots_proof="base64encodedproof",
        )

        d = header.to_dict()
        assert d["ots_proof"] == "base64encodedproof"

    def test_block_header_serialization_roundtrip(self, merkle_batcher):
        header = merkle_batcher.BlockHeader(
            version=1,
            site_id="test-site",
            day="2025-10-07",
            batch_id="test-site-2025-10-07-00",
            merkle_root="a" * 64,
            count=3,
            leaf_hashes=["b" * 64, "c" * 64, "d" * 64],
            ots_proof=None,
        )

        # Convert to dict and back to JSON
        d = header.to_dict()
        json_str = json.dumps(d)
        loaded = json.loads(json_str)

        # Verify all fields
        assert loaded["version"] == 1
        assert loaded["site_id"] == "test-site"
        assert loaded["count"] == 3
