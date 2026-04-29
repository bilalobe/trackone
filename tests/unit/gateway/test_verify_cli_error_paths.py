#!/usr/bin/env python3
"""
Error-path tests for verify_cli (moved from test_unit_coverage_boost.py)
"""

from __future__ import annotations

from unittest.mock import patch

from scripts.gateway import verify_cli


class TestVerifyCliErrorPaths:
    """Test error paths in verify_cli.py to cover lines 73-76, 87, 96-99."""

    def test_verify_ots_binary_ots_file(self, tmp_path):
        """Test verify_ots with binary OTS file (not UTF-8 decodable)."""
        ots_file = tmp_path / "test.ots"
        # Write binary data that's not valid UTF-8
        ots_file.write_bytes(b"\x00\xff\xfe\xfd\xfc")

        # Should fall through to real OTS verification attempt
        # Since we don't have ots binary in tests, it should return False
        result = verify_cli.verify_ots(ots_file)
        assert result is False

    def test_verify_ots_ots_not_executable(self, tmp_path):
        """Test verify_ots when ots path exists but is not executable."""
        ots_file = tmp_path / "test.ots"
        ots_file.write_text("some ots data", encoding="utf-8")

        fake_ots = tmp_path / "fake_ots"
        fake_ots.write_text("#!/bin/sh\necho test", encoding="utf-8")
        # Don't make it executable

        with patch("shutil.which", return_value=str(fake_ots)):
            result = verify_cli.verify_ots(ots_file)
            assert result is False

    def test_verify_ots_public_boundary_exec_failure(self, tmp_path):
        """Test verify_ots when the public OTS boundary reports exec failure."""
        ots_file = tmp_path / "test.ots"
        ots_file.write_text("some ots data", encoding="utf-8")

        fake_ots = tmp_path / "fake_ots"
        fake_ots.write_text("#!/bin/sh\necho test", encoding="utf-8")
        fake_ots.chmod(0o755)

        with (
            patch("shutil.which", return_value=str(fake_ots)),
            patch.object(
                verify_cli.ots, "verify_ots_proof", return_value=False
            ) as verify,
        ):
            result = verify_cli.verify_ots(ots_file)
            assert result is False
            verify.assert_called_once_with(
                str(ots_file),
                allow_placeholder=True,
                expected_artifact_sha=None,
                ots_binary=str(fake_ots),
                timeout_secs=verify_cli.OTS_VERIFY_TIMEOUT_SECS,
            )

    def test_verify_ots_ots_path_is_directory(self, tmp_path):
        """Test verify_ots when resolved ots path is a directory, not a file."""
        ots_file = tmp_path / "test.ots"
        ots_file.write_text("some ots data", encoding="utf-8")

        fake_ots_dir = tmp_path / "fake_ots_dir"
        fake_ots_dir.mkdir()

        with patch("shutil.which", return_value=str(fake_ots_dir)):
            result = verify_cli.verify_ots(ots_file)
            # Should return False because path is not a file
            assert result is False

    def test_verify_ots_public_boundary_timeout(self, tmp_path):
        """Test verify_ots when the public OTS boundary reports timeout."""
        ots_file = tmp_path / "test.ots"
        ots_file.write_text("some ots data", encoding="utf-8")

        fake_ots = tmp_path / "fake_ots"
        fake_ots.write_text("#!/bin/sh\necho test", encoding="utf-8")
        fake_ots.chmod(0o755)

        with (
            patch("shutil.which", return_value=str(fake_ots)),
            patch.object(
                verify_cli.ots, "verify_ots_proof", return_value=False
            ) as verify,
        ):
            result = verify_cli.verify_ots(ots_file)
            assert result is False
            verify.assert_called_once_with(
                str(ots_file),
                allow_placeholder=True,
                expected_artifact_sha=None,
                ots_binary=str(fake_ots),
                timeout_secs=verify_cli.OTS_VERIFY_TIMEOUT_SECS,
            )
