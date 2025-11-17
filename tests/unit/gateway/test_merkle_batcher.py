#!/usr/bin/env python3
"""
Edge cases for merkle_batcher (moved from test_edge_cases.py)
"""
from __future__ import annotations

import json

import pytest


@pytest.fixture(scope="module", autouse=True)
def _load_modules(gateway_modules):
    """Load required gateway modules."""
    merkle_batcher = gateway_modules.get("merkle_batcher")
    if merkle_batcher is None:
        pytest.skip("Required gateway module 'merkle_batcher' not available")
    return merkle_batcher


class TestMerkleBatcherEdgeCases:
    """Test edge cases in merkle_batcher."""

    def test_batcher_with_empty_facts_dir(self, tmp_path, facts_dir, merkle_batcher):
        """Empty facts directory should be handled."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test",
            "--date",
            "2025-10-07",
            "--allow-empty",
        ]

        result = merkle_batcher.main(args)
        assert result == 0

    def test_batcher_invalid_date_format(self, tmp_path, facts_dir, merkle_batcher):
        """Invalid date format should be rejected."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        # Create a fact file
        fact_file = facts_dir / "fact.json"
        fact_file.write_text(
            json.dumps(
                {
                    "device_id": "test",
                    "timestamp": "2025-10-07T10:00:00Z",
                    "nonce": "abc123",
                    "payload": {},
                }
            )
        )

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            "test",
            "--date",
            "invalid-date",
        ]

        result = merkle_batcher.main(args)
        # Should fail gracefully
        assert result != 0

    def test_batcher_nonexistent_facts_dir(self, tmp_path, merkle_batcher):
        """Nonexistent facts directory should be handled."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        args = [
            "--facts",
            str(tmp_path / "nonexistent"),
            "--out",
            str(out_dir),
            "--site",
            "test",
            "--date",
            "2025-10-07",
        ]

        result = merkle_batcher.main(args)
        assert result != 0

    @pytest.mark.parametrize(
        "site_id",
        [
            "site-001",
            "s",
            "a" * 50,
            "site_with_underscore",
        ],
    )
    def test_batcher_various_site_ids(
        self, tmp_path, facts_dir, merkle_batcher, site_id
    ):
        """Test various site ID formats."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        fact_file = facts_dir / "fact.json"
        fact_file.write_text(
            json.dumps(
                {
                    "device_id": "test",
                    "timestamp": "2025-10-07T10:00:00Z",
                    "nonce": "abc123",
                    "payload": {},
                }
            )
        )

        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            site_id,
            "--date",
            "2025-10-07",
        ]

        result = merkle_batcher.main(args)
        assert result == 0
