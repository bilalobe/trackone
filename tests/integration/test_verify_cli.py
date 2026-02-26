#!/usr/bin/env python3
"""
Verify CLI integration tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations

import json

from scripts.gateway.canonical_cbor import canonicalize_obj_to_cbor


class TestVerifyCli:
    def test_merkle_root_computation_matches_batcher(
        self, sample_facts, verify_cli, merkle_batcher
    ):
        leaves = [canonicalize_obj_to_cbor(f) for f in sample_facts]
        verify_root = verify_cli.merkle_root(leaves)
        batcher_root, _ = merkle_batcher.merkle_root_from_leaves(leaves)
        assert verify_root == batcher_root

    def test_end_to_end_verification(
        self,
        temp_workspace,
        sample_facts,
        write_sample_facts_fixture,
        write_ots_placeholder,
        merkle_batcher,
        verify_cli,
    ):
        write_sample_facts_fixture(temp_workspace["facts_dir"], sample_facts)
        batcher_args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]
        assert merkle_batcher.main(batcher_args) == 0

        write_ots_placeholder(temp_workspace["out_dir"], "2025-10-07")

        fact_files = sorted(temp_workspace["facts_dir"].glob("*.cbor"))
        leaves = []
        for fpath in fact_files:
            leaves.append(fpath.read_bytes())

        recomputed_root = verify_cli.merkle_root(leaves)

        block_path = temp_workspace["out_dir"] / "blocks" / "2025-10-07-00.block.json"
        block_header = json.loads(block_path.read_text())
        recorded_root = block_header["merkle_root"]

        assert recomputed_root == recorded_root
