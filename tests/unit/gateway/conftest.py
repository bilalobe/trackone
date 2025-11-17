#!/usr/bin/env python3
"""
Gateway-scoped fixtures for unit tests under scripts/tests/unit/gateway.
Copied from scripts/tests/fixtures/gateway_fixtures.py to decouple tests.
"""
from __future__ import annotations

import pytest


@pytest.fixture(scope="module")
def frame_verifier(gateway_modules):
    """Load frame_verifier module from gateway modules (module-scoped).

    Provides frame verification and TLV decoding functionality.
    """
    module = gateway_modules.get("frame_verifier")
    if module is None:
        pytest.skip("frame_verifier module not available")
    return module


@pytest.fixture(scope="module")
def merkle_batcher(gateway_modules):
    """Load merkle_batcher module from gateway modules (module-scoped).

    Provides fact batching and Merkle tree operations.
    """
    module = gateway_modules.get("merkle_batcher")
    if module is None:
        pytest.skip("merkle_batcher module not available")
    return module


@pytest.fixture(scope="module")
def verify_cli(gateway_modules):
    """Load verify_cli module from gateway modules (module-scoped).

    Provides OTS verification CLI functionality.
    """
    module = gateway_modules.get("verify_cli")
    if module is None:
        pytest.skip("verify_cli module not available")
    return module


@pytest.fixture
def crypto_utils(gateway_modules):
    """Provide crypto_utils module (function-scoped for individual test use).

    Provides cryptographic primitives: X25519, HKDF, ChaCha20-Poly1305,
    XChaCha20-Poly1305, Ed25519.
    """
    module = gateway_modules.get("crypto_utils")
    if module is None:
        pytest.skip("crypto_utils module not available")
    return module


@pytest.fixture(scope="module")
def crypto_utils_module(gateway_modules):
    """Provide crypto_utils module (module-scoped).

    Use this when you need module-scope lifetime for crypto operations.
    """
    module = gateway_modules.get("crypto_utils")
    if module is None:
        pytest.skip("crypto_utils module not available")
    return module


@pytest.fixture(scope="module")
def ots_anchor(gateway_modules):
    """Load ots_anchor module from gateway modules (module-scoped).

    Provides OTS stamping and placeholder functionality.
    """
    module = gateway_modules.get("ots_anchor")
    if module is None:
        pytest.skip("ots_anchor module not available")
    return module


@pytest.fixture
def write_frames():
    """Return a minimal callable that invokes the canonical pod_sim to write frames.

    This is intentionally small and synchronous for unit tests.
    """

    def _write(device_id: str, count: int, out_path, *maybe):
        import subprocess
        import sys
        from pathlib import Path

        device_table = None
        facts_out = None
        if len(maybe) == 1:
            device_table = maybe[0]
        elif len(maybe) >= 2:
            if maybe[0] is None:
                device_table = maybe[1]
            else:
                device_table = maybe[0]
                facts_out = maybe[1]

        if isinstance(device_table, str):
            device_table = Path(device_table)
        if isinstance(facts_out, str):
            facts_out = Path(facts_out)

        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            "scripts/pod_sim/pod_sim.py",
            "--device-id",
            device_id,
            "--count",
            str(count),
            "--framed",
            "--out",
            str(out_path),
        ]
        if device_table:
            cmd += ["--device-table", str(device_table)]
        if facts_out and (
            device_table is None
            or Path(facts_out).resolve() != Path(device_table).resolve()
        ):
            cmd += ["--facts-out", str(facts_out)]
        subprocess.run(cmd, check=True)

    return _write


@pytest.fixture(scope="module")
def write_device_table():
    """Return a callable to write a device_table JSON file (module-scoped for gateway unit tests)."""
    import json
    from pathlib import Path

    def _write(path, data, indent: int | None = 2):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=indent), encoding="utf-8")

    return _write
