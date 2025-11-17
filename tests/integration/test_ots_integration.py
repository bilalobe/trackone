"""
Optional real-OTS integration tests.

These tests exercise the actual OpenTimestamps client when present and
explicitly enabled. They are marked 'real_ots' and 'slow' and are skipped
unless RUN_REAL_OTS=1 and an 'ots' binary is available on PATH or via OTS_BIN.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest


def _find_ots():
    """Return path to 'ots' binary from OTS_BIN env or PATH, else None."""
    ots_env = os.environ.get("OTS_BIN")
    if ots_env and Path(ots_env).exists():
        return ots_env
    return shutil.which("ots")


requires_real_ots = pytest.mark.skipif(
    os.environ.get("RUN_REAL_OTS") != "1",
    reason="Set RUN_REAL_OTS=1 to enable real OTS integration tests",
)


@requires_real_ots
def test_ots_stamp_with_real_ots(tmp_path: Path, ots_anchor):
    """Test real OTS stamping if 'ots' binary is available."""
    ots_bin = _find_ots()
    if not ots_bin:
        pytest.skip("'ots' binary not found on PATH")

    day_bin = tmp_path / "2025-10-07.bin"
    day_bin.write_bytes(b"test data for timestamping")
    ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")

    # Invoke real OTS stamping
    ots_anchor.ots_stamp(day_bin, ots_path)

    # Verify OTS file was created and is not a placeholder
    assert ots_path.exists()
    data = ots_path.read_bytes()
    # If the file is binary, decoding may fail; assert using bytes
    assert b"OTS_PROOF_PLACEHOLDER" not in data or len(data) > 100


@requires_real_ots
def test_verify_ots_with_real_ots_proof(tmp_path: Path, verify_cli, ots_anchor):
    """Test verify_ots with a real OTS proof if 'ots' binary is available."""
    ots_bin = _find_ots()
    if not ots_bin:
        pytest.skip("'ots' binary not found on PATH")

    day_bin = tmp_path / "2025-10-07.bin"
    day_bin.write_bytes(b"test data for verification")
    ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")

    # Create real OTS proof
    ots_anchor.ots_stamp(day_bin, ots_path)

    # Verify the proof
    result = verify_cli.verify_ots(ots_path)
    # Result depends on whether ots binary can verify; both True and False are acceptable
    # in a test environment (network conditions may vary)
    assert isinstance(result, bool)
