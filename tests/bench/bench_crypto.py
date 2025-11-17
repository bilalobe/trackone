from __future__ import annotations

import secrets
from typing import Any

import pytest

# Import the canonical crypto utilities
from scripts.gateway import crypto_utils


def test_hkdf_sha256_32b(benchmark):
    """HKDF-SHA256 deriving 32 bytes."""

    def fn() -> bytes:
        return crypto_utils.hkdf_sha256(b"input-ikm", None, None, 32)

    out = benchmark(fn)
    assert isinstance(out, bytes) and len(out) == 32


@pytest.mark.parametrize("size", [64, 512, 4096])
def test_xchacha_encrypt_decrypt_roundtrip(benchmark, size: int):
    """Encrypt+decrypt roundtrip for XChaCha20-Poly1305 with varied payload sizes."""
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(24)
    pt = secrets.token_bytes(size)

    def fn() -> Any:
        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(key, nonce, pt)
        return crypto_utils.xchacha20poly1305_ietf_decrypt(key, nonce, ct, tag)

    out = benchmark(fn)
    assert isinstance(out, bytes) and len(out) == size
