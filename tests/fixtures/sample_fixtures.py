"""
Sample data fixtures for tests.

Common sample data used across multiple test suites.
"""

from __future__ import annotations

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
