"""
Sample data fixtures for tests.

Common sample data used across multiple test suites.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def sample_facts(test_timestamp) -> list[dict[str, Any]]:
    """Return a list of sample fact dictionaries for testing.

    Contains 3 devices with different timestamps and payloads.
    Note: Function-scoped because it depends on test_timestamp which is function-scoped.
    """
    return [
        {
            "device_id": "test-pod-01",
            "timestamp": test_timestamp(0),
            "nonce": "a1b2c3d4e5f601234567",
            "payload": {"temperature": 22.5, "humidity": 45},
        },
        {
            "device_id": "test-pod-02",
            "timestamp": test_timestamp(300),
            "nonce": "b2c3d4e5f601234567a8",
            "payload": {"temperature": 23.1, "humidity": 48},
        },
        {
            "device_id": "test-pod-03",
            "timestamp": test_timestamp(600),
            "nonce": "c3d4e5f601234567b9a9",
            "payload": {"temperature": 21.8, "humidity": 42},
        },
    ]


@pytest.fixture(scope="module")
def sample_test_vectors() -> dict[str, Any]:
    """Return sample cryptographic test vectors for X25519 and HKDF (module-scoped)."""
    return {
        "x25519_vectors": [
            {
                "description": "Basic key agreement",
                "alice_private": "a0" * 32,
                "bob_private": "b0" * 32,
            }
        ],
        "hkdf_vectors": [
            {
                "description": "Deterministic derivation",
                "ikm": "696e7075742d6b65792d6d6174657269616c",
                "salt": "7361 6c745f76616c7565",
                "info": "636f6e746578745f696e666f",
                "length": 32,
            }
        ],
    }


@pytest.fixture(scope="module")
def crypto_test_vectors_path() -> Path | None:
    """Return path to crypto test vectors file if it exists (module-scoped)."""
    path = Path(__file__).parent.parent / "pod_sim" / "crypto_test_vectors.json"
    if path.exists():
        return path
    return None


@pytest.fixture
def built_day_artifacts(
    tmp_path: Path,
    merkle_batcher,
    write_sample_facts_fixture,
    sample_facts,
    write_ots_placeholder,
) -> dict[str, Path]:
    """Build a minimal day.bin + .ots setup under a fresh temporary directory.

    Returns a mapping with:
    - root: output root directory
    - facts_dir: directory with JSON fact files
    - day_bin: path to day/YYYY-MM-DD.bin
    - ots_path: path to day/YYYY-MM-DD.bin.ots
    - date: the date string used ("2025-10-07")
    """
    facts_dir = tmp_path / "facts"
    out_dir = tmp_path / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_sample_facts_fixture(facts_dir, sample_facts)

    date = "2025-10-07"
    args = [
        "--facts",
        str(facts_dir),
        "--out",
        str(out_dir),
        "--site",
        "test-site",
        "--date",
        date,
    ]
    assert merkle_batcher.main(args) == 0

    day_bin = out_dir / "day" / f"{date}.bin"
    assert day_bin.exists()

    ots_path, meta_path = write_ots_placeholder(out_dir, date)
    assert ots_path.exists()
    assert meta_path.exists()

    return {
        "root": out_dir,
        "facts_dir": facts_dir,
        "day_bin": day_bin,
        "ots_path": ots_path,
        "date": Path(date),
    }


@pytest.fixture
def mutate_day_bin() -> Callable[[Path], None]:
    """Return a function that corrupts a day.bin file in a minimal, detectable way."""

    def _mutate(path: Path) -> None:
        with path.open("ab") as f:
            f.write(b"X")

    return _mutate


@pytest.fixture
def mutate_ots_file() -> Callable[[Path], tuple[bytes, bytes]]:
    """Return a function that mutates an .ots file and yields (original, mutated) bytes.

    Useful for tests that want to restore the original contents after assertions.
    For stationary stubs, this corrupts the embedded SHA-256 hash.
    """

    def _mutate(path: Path) -> tuple[bytes, bytes]:
        original = path.read_bytes()

        # Check if this is a stationary stub and corrupt the hash if so
        if original.startswith(b"STATIONARY-OTS:"):
            # Corrupt the hash by replacing the last character with 'X'
            mutated = original.rstrip()
            if len(mutated) > 16:  # Has a hash
                mutated = mutated[:-1] + b"X"
            mutated += b"\n"
        else:
            # For real OTS proofs, append bytes
            mutated = original + b"\n# upgraded proof bytes (simulated)\n"

        path.write_bytes(mutated)
        return original, mutated

    return _mutate
