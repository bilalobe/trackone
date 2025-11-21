#!/usr/bin/env python3
"""
Tests for OTS stamp behavior (moved from test_ots_anchor.py)
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

# Disable stationary stub mode for all tests in this module
pytestmark = pytest.mark.usefixtures("disable_stationary_stub")


class TestOTSStamp:
    """Test OTS stamping functionality.

    These tests exercise the real ots client code paths (with mocked subprocess.run)
    rather than the stationary stub mode.
    """

    @pytest.mark.parametrize(
        "exc",
        [OSError("ots not found"), PermissionError("perm"), FileNotFoundError("nf")],
    )
    def test_ots_stamp_creates_placeholder_when_ots_unavailable(
        self, exc, tmp_path, ots_anchor
    ):
        """When OTS client is not available, should create placeholder file deterministically."""
        day_bin = tmp_path / "2025-10-07.bin"
        day_bin.write_bytes(b"test data")
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")

        # Force error starting the process → placeholder path
        with patch("subprocess.run", side_effect=exc):
            ots_anchor.ots_stamp(day_bin, ots_path)

        assert ots_path.exists()
        content = ots_path.read_text(encoding="utf-8")
        assert "OTS_PROOF_PLACEHOLDER" in content

    @patch("subprocess.run")
    def test_ots_stamp_calls_ots_command(self, mock_run, tmp_path, ots_anchor):
        """When OTS client is available, should call ots stamp command (and upgrade best-effort)."""
        day_bin = tmp_path / "2025-10-07.bin"
        day_bin.write_bytes(b"test data")
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")

        # Mock successful OTS commands
        mock_run.return_value = MagicMock(returncode=0)

        # Simulate OTS client creating the proof file
        ots_path.write_text("OTS_PROOF_DATA\n", encoding="utf-8")

        ots_anchor.ots_stamp(day_bin, ots_path)

        # Validate the first call was to 'ots stamp <bin>' with check=True
        first_call = mock_run.call_args_list[0]
        from unittest.mock import call

        assert first_call == call(
            ["ots", "stamp", str(day_bin)],
            check=True,
            env=mock_run.call_args_list[0][1]["env"],
        )

        # Validate that an upgrade was attempted best-effort afterward
        assert any("upgrade" in str(c) for c in mock_run.call_args_list)

    @patch("subprocess.run")
    def test_ots_stamp_fallback_on_command_failure(
        self, mock_run, tmp_path, ots_anchor
    ):
        """If OTS command fails, should fall back to placeholder."""
        day_bin = tmp_path / "2025-10-07.bin"
        day_bin.write_bytes(b"test data")
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")

        # Mock OTS command failure
        mock_run.side_effect = subprocess.CalledProcessError(1, "ots")

        ots_anchor.ots_stamp(day_bin, ots_path)

        assert ots_path.exists()
        content = ots_path.read_text(encoding="utf-8")
        assert "OTS_PROOF_PLACEHOLDER" in content

    @patch("subprocess.run")
    def test_ots_stamp_creates_placeholder_if_ots_doesnt_create_file(
        self, mock_run, tmp_path, ots_anchor
    ):
        """If OTS command succeeds but doesn't create .ots file, create placeholder."""
        day_bin = tmp_path / "2025-10-07.bin"
        day_bin.write_bytes(b"test data")
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")

        # Mock successful command but don't create .ots file
        mock_run.return_value = MagicMock(returncode=0)

        ots_anchor.ots_stamp(day_bin, ots_path)

        # Should create placeholder
        assert ots_path.exists()
        content = ots_path.read_text(encoding="utf-8")
        assert "OTS_PROOF_PLACEHOLDER" in content
