#!/usr/bin/env python3
"""
End-to-end merkle_batcher tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations

import json
from hashlib import sha256


class TestMerkleBatcher:
    def test_batcher_with_sample_facts(
        self, temp_workspace, sample_facts, write_sample_facts_fixture
    ):
        write_sample_facts_fixture(temp_workspace["facts_dir"], sample_facts)
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]

        result = batcher_main(args)
        assert result == 0

        # Check outputs exist
        block_path = temp_workspace["out_dir"] / "blocks" / "2025-10-07-00.block.json"
        day_bin_path = temp_workspace["out_dir"] / "day" / "2025-10-07.bin"
        day_json_path = temp_workspace["out_dir"] / "day" / "2025-10-07.json"

        assert block_path.exists()
        assert day_bin_path.exists()
        assert day_json_path.exists()

        # Validate block header structure
        block_header = json.loads(block_path.read_text())
        assert block_header["version"] == 1
        assert block_header["site_id"] == "test-site"
        assert block_header["day"] == "2025-10-07"
        assert block_header["count"] == 3
        assert len(block_header["leaf_hashes"]) == 3
        assert len(block_header["merkle_root"]) == 64

        # Validate day record structure
        day_record = json.loads(day_json_path.read_text())
        assert day_record["version"] == 1
        assert day_record["site_id"] == "test-site"
        assert day_record["date"] == "2025-10-07"
        assert len(day_record["prev_day_root"]) == 64
        assert day_record["day_root"] == block_header["merkle_root"]
        assert len(day_record["batches"]) == 1

    def test_batcher_with_schema_validation(
        self, temp_workspace, sample_facts, write_sample_facts_fixture
    ):
        write_sample_facts_fixture(temp_workspace["facts_dir"], sample_facts)
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
            "--validate-schemas",
        ]

        result = batcher_main(args)
        assert result == 0

    def test_batcher_empty_facts_fails_without_flag(self, temp_workspace):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
        ]

        result = batcher_main(args)
        assert result == 1  # Should fail with no facts

    def test_batcher_empty_facts_succeeds_with_flag(self, temp_workspace):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025-10-07",
            "--allow-empty",
        ]

        result = batcher_main(args)
        assert result == 0

        # Check that merkle root is sha256("")
        block_path = temp_workspace["out_dir"] / "blocks" / "2025-10-07-00.block.json"
        block_header = json.loads(block_path.read_text())
        assert block_header["merkle_root"] == sha256(b"").hexdigest()

    def test_batcher_invalid_date_format(self, temp_workspace):
        args = [
            "--facts",
            str(temp_workspace["facts_dir"]),
            "--out",
            str(temp_workspace["out_dir"]),
            "--site",
            "test-site",
            "--date",
            "2025/10/07",  # Invalid format
        ]

        result = batcher_main(args)
        assert result == 2
