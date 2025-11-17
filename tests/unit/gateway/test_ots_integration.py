#!/usr/bin/env python3
"""
Integration tests for OTS workflow (moved from test_ots_anchor.py)
"""
from __future__ import annotations

from unittest.mock import patch


class TestOTSIntegration:
    """Integration tests for OTS workflow."""

    def test_stamp_verify_workflow_with_placeholder(self, tmp_path, ots_anchor):
        """Test complete workflow: create day blob, stamp, verify placeholder exists."""
        # Create a day blob
        day_bin = tmp_path / "2025-10-07.bin"
        test_data = b"merkle_root_hash" + b"block_data" * 100
        day_bin.write_bytes(test_data)

        # Stamp it (force placeholder path)
        with patch("subprocess.run", side_effect=OSError("ots not found")):
            result = ots_anchor.main([str(day_bin)])
        assert result == 0

        # Verify .ots file exists
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
        assert ots_path.exists()
        assert ots_path.stat().st_size > 0

    def test_multiple_days_stamping(self, tmp_path, ots_anchor):
        """Test stamping multiple day blobs."""
        dates = ["2025-10-05", "2025-10-06", "2025-10-07"]

        for date in dates:
            day_bin = tmp_path / f"{date}.bin"
            day_bin.write_bytes(f"data for {date}".encode())

            with patch("subprocess.run", side_effect=OSError("ots not found")):
                result = ots_anchor.main([str(day_bin)])
            assert result == 0

            ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
            assert ots_path.exists()

    def test_ots_file_has_correct_suffix(self, tmp_path, ots_anchor):
        """Verify .ots file has correct double suffix (.bin.ots)."""
        day_bin = tmp_path / "2025-10-07.bin"
        day_bin.write_bytes(b"test")

        with patch("subprocess.run", side_effect=OSError("ots not found")):
            result = ots_anchor.main([str(day_bin)])
        assert result == 0

        # Check that it's .bin.ots, not .ots replacing .bin
        ots_path = tmp_path / "2025-10-07.bin.ots"
        assert ots_path.exists()
        assert not (tmp_path / "2025-10-07.ots").exists()
