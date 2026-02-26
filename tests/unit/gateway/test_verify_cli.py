#!/usr/bin/env python3
"""
Edge cases for verify_cli (moved from test_edge_cases.py)
"""
from __future__ import annotations


class TestVerifyCliEdgeCases:
    """Test edge cases in verify_cli."""

    def test_verify_nonexistent_root_dir(self, tmp_path, verify_cli, facts_dir):
        """Nonexistent root directory should be handled."""
        args = [
            "--root",
            str(tmp_path / "nonexistent"),
            "--facts",
            str(facts_dir),
        ]

        result = verify_cli.main(args)
        # Expect specific error code for missing block header
        assert isinstance(result, int)
        assert result == 1

    def test_verify_empty_day_directory(self, tmp_path, verify_cli, facts_dir):
        """Empty day directory should be handled."""
        root = tmp_path / "out"
        day_dir = root / "day"
        block_dir = root / "block"

        day_dir.mkdir(parents=True)
        block_dir.mkdir(parents=True)

        args = [
            "--root",
            str(root),
            "--facts",
            str(facts_dir),
        ]

        result = verify_cli.main(args)
        # No block header -> specific return code
        assert result == 1

    def test_verify_missing_ots_file(self, tmp_path, verify_cli, facts_dir):
        """Missing OTS file should be handled."""
        root = tmp_path / "out"
        day_dir = root / "day"

        day_dir.mkdir(parents=True)

        # Create day.cbor but no .ots file
        day_bin = day_dir / "2025-10-07.cbor"
        day_bin.write_bytes(b"test data")

        args = [
            "--root",
            str(root),
            "--facts",
            str(facts_dir),
        ]

        result = verify_cli.main(args)
        # Missing block header -> return code 1 (no block header found)
        assert result == 1
