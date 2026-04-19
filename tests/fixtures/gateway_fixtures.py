#!/usr/bin/env python3
"""
Gateway module loader fixtures.

Provides fixtures for loading gateway script modules (frame_verifier, merkle_batcher,
verify_cli, ots_anchor, crypto_utils) via the centralized gateway_modules loader.

These fixtures replace the scattered module-specific loaders in various conftest.py files.
"""

from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def frame_verifier(gateway_modules):
    """Load frame_verifier module (module-scoped).

    Provides frame verification and Rust-authoritative postcard framed ingest.
    """
    module = gateway_modules.get("frame_verifier")
    if module is None:
        pytest.skip("frame_verifier module not available")
    return module


@pytest.fixture(scope="module")
def merkle_batcher(gateway_modules):
    """Load merkle_batcher module (module-scoped).

    Provides fact batching and Merkle tree operations.
    """
    module = gateway_modules.get("merkle_batcher")
    if module is None:
        pytest.skip("merkle_batcher module not available")
    return module


@pytest.fixture(scope="module")
def verify_cli(gateway_modules):
    """Load verify_cli module (module-scoped).

    Provides OTS verification CLI functionality.
    """
    module = gateway_modules.get("verify_cli")
    if module is None:
        pytest.skip("verify_cli module not available")
    return module


@pytest.fixture(scope="module")
def ots_anchor(gateway_modules):
    """Load ots_anchor module (module-scoped).

    Provides OTS stamping and placeholder functionality.
    """
    module = gateway_modules.get("ots_anchor")
    if module is None:
        pytest.skip("ots_anchor module not available")
    return module


@pytest.fixture(scope="module")
def crypto_utils(gateway_modules):
    """Load crypto_utils module (module-scoped).

    Provides cryptographic primitives: X25519, HKDF, ChaCha20-Poly1305,
    XChaCha20-Poly1305, Ed25519.
    """
    module = gateway_modules.get("crypto_utils")
    if module is None:
        pytest.skip("crypto_utils module not available")
    return module


@pytest.fixture(scope="module")
def pod_sim(load_module):
    """Load pod_sim module (module-scoped).

    Provides reference fact generation, device table helpers, and CLI
    functionality.
    """
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[2]
    pod_sim_path = repo_root / "scripts" / "pod_sim" / "pod_sim.py"
    if not pod_sim_path.exists():
        pytest.skip(f"pod_sim not found at {pod_sim_path}")
    return load_module("pod_sim", pod_sim_path)
