"""
HKDF-SHA256 key derivation tests.

Tests for HMAC-based Key Derivation Function (RFC 5869).
"""

from __future__ import annotations

from scripts.gateway import crypto_utils


class TestHKDF:
    """Test HKDF-SHA256 key derivation functionality."""

    def test_deterministic_derivation(self):
        """Test HKDF produces deterministic output."""
        ikm = b"input_key_material" * 2
        salt = b"salt_value"
        info = b"context_info"

        okm1 = crypto_utils.hkdf_sha256(ikm, salt, info, 32)
        okm2 = crypto_utils.hkdf_sha256(ikm, salt, info, 32)

        assert okm1 == okm2
        assert len(okm1) == 32

    def test_different_info_produces_different_keys(self):
        """Test different info strings produce different output."""
        ikm = b"\x42" * 32
        salt = b"\x00" * 16

        okm1 = crypto_utils.hkdf_sha256(ikm, salt, b"context1", 32)
        okm2 = crypto_utils.hkdf_sha256(ikm, salt, b"context2", 32)

        assert okm1 != okm2

    def test_different_salt_produces_different_keys(self):
        """Test different salt values produce different output."""
        ikm = b"\x42" * 32
        info = b"context"

        okm1 = crypto_utils.hkdf_sha256(ikm, b"salt1", info, 32)
        okm2 = crypto_utils.hkdf_sha256(ikm, b"salt2", info, 32)

        assert okm1 != okm2

    def test_different_lengths_produce_different_output(self):
        """Test that requesting different output lengths works correctly."""
        ikm = b"input"
        salt = b"salt"
        info = b"info"

        okm16 = crypto_utils.hkdf_sha256(ikm, salt, info, 16)
        okm32 = crypto_utils.hkdf_sha256(ikm, salt, info, 32)
        okm64 = crypto_utils.hkdf_sha256(ikm, salt, info, 64)

        assert len(okm16) == 16
        assert len(okm32) == 32
        assert len(okm64) == 64
        # Per RFC 5869 the first N bytes of a longer OKM match the OKM of length N
        assert okm32[:16] == okm16

    def test_hkdf_empty_salt(self):
        """Test HKDF with empty salt."""
        ikm = b"input"
        info = b"context"

        okm1 = crypto_utils.hkdf_sha256(ikm, b"", info, 32)
        okm2 = crypto_utils.hkdf_sha256(ikm, b"", info, 32)

        assert okm1 == okm2
        assert len(okm1) == 32

    def test_hkdf_empty_info(self):
        """Test HKDF with empty info."""
        ikm = b"input"
        salt = b"salt"

        okm = crypto_utils.hkdf_sha256(ikm, salt, b"", 32)
        assert len(okm) == 32
