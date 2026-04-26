from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.gateway.config import get_bool_env


def test_day_cbor_sha256_sidecar_matches_out_dir_env():
    """
    When OUT_DIR is set by an artifact-verification CI path, verify that every
    day/*.cbor has a sibling *.cbor.sha256 file containing the correct hex digest.
    """
    out_dir = os.environ.get("OUT_DIR")
    if not out_dir:
        pytest.skip("OUT_DIR not set; sha artifact verification is CI-only")

    day_dir = Path(out_dir)
    strict = get_bool_env("STRICT_SHA", default=False)
    if not day_dir.exists():
        if strict:
            pytest.fail(f"OUT_DIR does not exist: {day_dir}")
        pytest.skip(f"OUT_DIR does not exist: {day_dir}")

    cbor_files = sorted(day_dir.glob("*.cbor"))
    if not cbor_files:
        if strict:
            pytest.fail(f"No *.cbor artifacts found under OUT_DIR={day_dir}")
        pytest.skip(f"No *.cbor artifacts found under OUT_DIR={day_dir}")

    for cbor_path in cbor_files:
        sha_path = cbor_path.with_suffix(cbor_path.suffix + ".sha256")
        if not sha_path.exists():
            pytest.fail(f"Missing sha256 sidecar for {cbor_path}: expected {sha_path}")

        declared = sha_path.read_text(encoding="utf-8").strip()
        assert len(declared) == 64, f"Invalid sha256 hex length in {sha_path}"

        actual = sha256(cbor_path.read_bytes()).hexdigest()
        assert actual == declared, (
            f"sha256 mismatch for {cbor_path}: declared={declared} actual={actual}"
        )
