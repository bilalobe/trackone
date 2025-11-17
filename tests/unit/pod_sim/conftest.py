#!/usr/bin/env python3
"""
Pod-sim scoped fixtures for unit tests under scripts/tests/unit/pod_sim.
Copied from scripts/tests/fixtures/pod_sim_fixtures.py to decouple tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def pod_sim(load_module):
    """Load pod_sim module from scripts/pod_sim/pod_sim.py (module-scoped).

    Provides fact generation, TLV encoding, device table management, and CLI functionality.
    """
    repo_root = Path(__file__).resolve().parents[3]
    pod_sim_path = repo_root / "scripts" / "pod_sim" / "pod_sim.py"
    if not pod_sim_path.exists():
        raise FileNotFoundError(
            f"Canonical pod_sim implementation not found at {pod_sim_path}"
        )
    return load_module("pod_sim", pod_sim_path)


@pytest.fixture
def test_vectors():
    import json

    # The repository layout places this file at tests/unit/pod_sim/conftest.py
    # Parents[3] is the repository root in that layout; use it directly rather
    # than performing an upward search.
    repo_root = Path(__file__).resolve().parents[3]
    vectors_path = repo_root / "toolset" / "unified" / "crypto_test_vectors.json"
    if not vectors_path.exists():
        pytest.skip(f"Test vectors file not found: {vectors_path}")
    return json.loads(vectors_path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def frame_verifier(gateway_modules):
    """Provide frame_verifier module (module-scoped for pod_sim unit tests)."""
    module = gateway_modules.get("frame_verifier")
    if module is None:
        pytest.skip("frame_verifier module not available")
    return module


@pytest.fixture(scope="module")
def write_device_table():
    """Return a callable to write a device_table JSON file (module-scoped for pod_sim tests)."""
    import json

    def _write(path, data, indent: int | None = 2):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=indent), encoding="utf-8")

    return _write
