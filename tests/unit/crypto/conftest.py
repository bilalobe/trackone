"""
Crypto unit tests fixtures (module-scoped).
"""

from __future__ import annotations

import pytest

from scripts.gateway import crypto_utils as _crypto_utils


@pytest.fixture(scope="module")
def crypto_utils():
    """Provide crypto_utils module (module-scoped for crypto unit tests)."""
    return _crypto_utils


@pytest.fixture(scope="module")
def merkle_batcher(gateway_modules):
    """Provide merkle_batcher module (module-scoped for crypto unit tests)."""
    module = gateway_modules.get("merkle_batcher")
    if module is None:
        pytest.skip("merkle_batcher module not available")
    return module
