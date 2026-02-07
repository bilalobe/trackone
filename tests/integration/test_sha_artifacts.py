from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path

import pytest


def _bool_env(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip() not in {"", "0", "false", "False", "no", "NO"}


def test_day_bin_sha256_sidecar_matches_out_dir_env():
    """
    When OUT_DIR is set (CI sha-verify workflow), verify that every day/*.bin has a
    sibling *.bin.sha256 file containing the correct hex digest.
    """
    out_dir = os.environ.get("OUT_DIR")
    if not out_dir:
        pytest.skip("OUT_DIR not set; sha artifact verification is CI-only")

    day_dir = Path(out_dir)
    strict = _bool_env("STRICT_SHA", default=False)
    if not day_dir.exists():
        if strict:
            pytest.fail(f"OUT_DIR does not exist: {day_dir}")
        pytest.skip(f"OUT_DIR does not exist: {day_dir}")

    bin_files = sorted(day_dir.glob("*.bin"))
    if not bin_files:
        if strict:
            pytest.fail(f"No *.bin artifacts found under OUT_DIR={day_dir}")
        pytest.skip(f"No *.bin artifacts found under OUT_DIR={day_dir}")

    for bin_path in bin_files:
        sha_path = bin_path.with_suffix(bin_path.suffix + ".sha256")
        if not sha_path.exists():
            pytest.fail(f"Missing sha256 sidecar for {bin_path}: expected {sha_path}")

        declared = sha_path.read_text(encoding="utf-8").strip()
        assert len(declared) == 64, f"Invalid sha256 hex length in {sha_path}"

        actual = sha256(bin_path.read_bytes()).hexdigest()
        assert (
            actual == declared
        ), f"sha256 mismatch for {bin_path}: declared={declared} actual={actual}"
