#!/usr/bin/env python3
"""
Pod-sim unit test fixtures.

Note: pod_sim, frame_verifier, and write_device_table are now centralized in
tests/fixtures/ and auto-imported.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def test_vectors():
    """Load crypto test vectors for pod_sim unit tests."""
    # The repository layout places this file at tests/unit/pod_sim/conftest.py
    # Parents[3] is the repository root in that layout
    repo_root = Path(__file__).resolve().parents[3]
    vectors_path = repo_root / "toolset" / "unified" / "crypto_test_vectors.json"
    if not vectors_path.exists():
        pytest.skip(f"Test vectors file not found: {vectors_path}")
    return json.loads(vectors_path.read_text(encoding="utf-8"))
