#!/usr/bin/env python3
"""
Tests for OTS anchor main behavior (moved from test_ots_anchor.py)
"""
from __future__ import annotations

from unittest.mock import patch


class TestOTSMain:
    """Test OTS anchor main function."""

    def test_main_creates_ots_file(self, tmp_path, ots_anchor):
        """Main function should create .ots file without invoking real ots."""
        day_bin = tmp_path / "2025-10-07.bin"
        day_bin.write_bytes(b"test day blob")

        # Avoid calling the real 'ots' binary
        with patch("subprocess.run", side_effect=OSError("ots not found")):
            result = ots_anchor.main([str(day_bin)])

        assert result == 0
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
        assert ots_path.exists()
        assert "OTS_PROOF_PLACEHOLDER" in ots_path.read_text(encoding="utf-8")

    def test_main_with_nested_path(self, tmp_path, ots_anchor):
        """Main function should handle nested directory paths without invoking real ots."""
        day_dir = tmp_path / "out" / "day"
        day_dir.mkdir(parents=True)
        day_bin = day_dir / "2025-10-07.bin"
        day_bin.write_bytes(b"test day blob")

        with patch("subprocess.run", side_effect=OSError("ots not found")):
            result = ots_anchor.main([str(day_bin)])

        assert result == 0
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
        assert ots_path.exists()
        assert "OTS_PROOF_PLACEHOLDER" in ots_path.read_text(encoding="utf-8")

    def test_main_with_different_date_formats(self, tmp_path, ots_anchor):
        """Main function should work with various date formats in filename."""
        for filename in ["2025-10-07.bin", "2025-01-01.bin", "2025-12-31.bin"]:
            day_bin = tmp_path / filename
            day_bin.write_bytes(b"test data")

            with patch("subprocess.run", side_effect=OSError("ots not found")):
                result = ots_anchor.main([str(day_bin)])

            assert result == 0
            ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
            assert ots_path.exists()

            # Clean up for next iteration
            ots_path.unlink()
