#!/usr/bin/env python3
"""
BlockHeader edge case tests (moved from test_edge_cases.py)
"""
from __future__ import annotations

import json


class TestBlockHeader:
    """Test BlockHeader functionality."""

    def test_block_header_basic_creation(self, merkle_batcher):
        """BlockHeader should be created without ots_proof field."""
        header = merkle_batcher.BlockHeader(
            version=1,
            site_id="test",
            day="2025-10-07",
            batch_id="test-2025-10-07-00",
            merkle_root="a" * 64,
            count=0,
            leaf_hashes=[],
        )

        d = header.to_dict()
        assert "ots_proof" not in d
        assert d["version"] == 1
        assert d["site_id"] == "test"
        assert d["count"] == 0

    def test_block_header_serialization_roundtrip(self, merkle_batcher):
        """BlockHeader should serialize and deserialize correctly."""
        header = merkle_batcher.BlockHeader(
            version=1,
            site_id="test-site",
            day="2025-10-07",
            batch_id="test-site-2025-10-07-00",
            merkle_root="a" * 64,
            count=3,
            leaf_hashes=["b" * 64, "c" * 64, "d" * 64],
        )

        # Convert to dict and back to JSON
        d = header.to_dict()
        json_str = json.dumps(d)
        loaded = json.loads(json_str)

        # Verify all fields
        assert loaded["version"] == 1
        assert loaded["site_id"] == "test-site"
        assert loaded["count"] == 3
        assert "ots_proof" not in loaded
