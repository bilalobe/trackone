#!/usr/bin/env python3
"""
BlockHeader tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations


class TestBlockHeader:
    def test_block_header_to_dict(self):
        header = BlockHeader(
            version=1,
            site_id="test-site",
            day="2025-10-07",
            batch_id="test-site-2025-10-07-00",
            merkle_root="a" * 64,
            count=5,
            leaf_hashes=["b" * 64, "c" * 64],
            ots_proof=None,
        )
        d = header.to_dict()

        assert d["version"] == 1
        assert d["site_id"] == "test-site"
        assert d["day"] == "2025-10-07"
        assert d["merkle_root"] == "a" * 64
        assert d["count"] == 5
        assert len(d["leaf_hashes"]) == 2
