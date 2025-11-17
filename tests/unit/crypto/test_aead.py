"""
AEAD encryption tests.

Tests for AEAD ciphers:
- ChaCha20-Poly1305 (96-bit nonce)
- XChaCha20-Poly1305 (192-bit nonce)
"""

from __future__ import annotations

import json
from pathlib import Path

import nacl.exceptions
import pytest

from scripts.gateway import crypto_utils


class TestChaCha20Poly1305:
    """Test ChaCha20-Poly1305 AEAD (96-bit nonce)."""

    def test_encrypt_decrypt_round_trip(self):
        """Test ChaCha20-Poly1305 encryption and decryption."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        aad = b"additional_data"
        plaintext = b"secret message"

        ct, tag = crypto_utils.chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        recovered = crypto_utils.chacha20poly1305_decrypt(key, nonce, ct, tag, aad)

        assert recovered == plaintext

    def test_authentication_failure_on_ciphertext_tamper(self):
        """Test that tampering with ciphertext is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.chacha20poly1305_encrypt(key, nonce, pt, aad)

        # Tamper ciphertext
        ct_bad = bytes([ct[0] ^ 1]) + ct[1:]
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.chacha20poly1305_decrypt(key, nonce, ct_bad, tag, aad)

    def test_authentication_failure_on_tag_tamper(self):
        """Test that tampering with authentication tag is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.chacha20poly1305_encrypt(key, nonce, pt, aad)

        # Tamper tag
        tag_bad = bytes([tag[0] ^ 1]) + tag[1:]
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.chacha20poly1305_decrypt(key, nonce, ct, tag_bad, aad)

    def test_authentication_failure_on_aad_tamper(self):
        """Test that tampering with AAD is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.chacha20poly1305_encrypt(key, nonce, pt, aad)

        # Tamper AAD
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.chacha20poly1305_decrypt(key, nonce, ct, tag, b"different_aad")


class TestXChaCha20Poly1305:
    """Test XChaCha20-Poly1305 AEAD (192-bit nonce)."""

    def test_encrypt_decrypt_round_trip(self):
        """Test XChaCha20-Poly1305 encryption and decryption."""
        key = bytes(range(32))
        nonce = b"\x00" * 24
        aad = b"additional_data"
        plaintext = b"secret message with xchacha"

        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(
            key, nonce, plaintext, aad
        )
        recovered = crypto_utils.xchacha20poly1305_ietf_decrypt(
            key, nonce, ct, tag, aad
        )

        assert recovered == plaintext

    def test_authentication_failure_on_ciphertext_tamper(self):
        """Test that tampering with ciphertext is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 24
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(key, nonce, pt, aad)

        # Tamper ciphertext
        ct_bad = bytes([ct[0] ^ 1]) + ct[1:]
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.xchacha20poly1305_ietf_decrypt(key, nonce, ct_bad, tag, aad)

    def test_authentication_failure_on_tag_tamper(self):
        """Test that tampering with authentication tag is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 24
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(key, nonce, pt, aad)

        # Tamper tag
        tag_bad = bytes([tag[0] ^ 1]) + tag[1:]
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.xchacha20poly1305_ietf_decrypt(key, nonce, ct, tag_bad, aad)

    def test_authentication_failure_on_aad_tamper(self):
        """Test that tampering with AAD is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 24
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(key, nonce, pt, aad)

        # Tamper AAD
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.xchacha20poly1305_ietf_decrypt(
                key, nonce, ct, tag, b"different_aad"
            )

    def test_different_nonces_produce_different_ciphertexts(self):
        """Test that different nonces produce different ciphertexts."""
        key = bytes(range(32))
        nonce1 = b"\x00" * 24
        nonce2 = b"\x01" + b"\x00" * 23
        plaintext = b"same message"
        aad = b"aad"

        ct1, tag1 = crypto_utils.xchacha20poly1305_ietf_encrypt(
            key, nonce1, plaintext, aad
        )
        ct2, tag2 = crypto_utils.xchacha20poly1305_ietf_encrypt(
            key, nonce2, plaintext, aad
        )

        assert ct1 != ct2
        assert tag1 != tag2


class TestDeterministicAEADVectors:
    """Deterministic AEAD vector checks moved from the mother test file."""

    def test_chacha20poly1305_vector_matches(self):
        """Verify ciphertext and tag match deterministic vector exactly."""
        import nacl.bindings

        # Use the repo-local toolset under the project root (parents[3]).
        base = Path(__file__).resolve()
        vectors_path = (
            base.parents[3] / "toolset" / "unified" / "crypto_test_vectors.json"
        )
        if not vectors_path.exists():
            pytest.skip(f"Deterministic vectors file not found: {vectors_path}")
        data = json.loads(vectors_path.read_text(encoding="utf-8"))
        vecs = data.get("deterministic_aead_vectors", [])
        if not vecs:
            pytest.skip("No deterministic AEAD vectors present")
        v = vecs[0]

        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"])
        aad = bytes.fromhex(v["aad"])
        pt = bytes.fromhex(v["plaintext"])

        # Use PyNaCl for verification
        combined = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
            pt, aad, nonce, key
        )
        ct, tag = combined[:-16], combined[-16:]

        assert ct.hex() == v["ciphertext"], "Ciphertext mismatch"
        assert tag.hex() == v["tag"], "Tag mismatch"

    def test_xchacha20poly1305_vector_matches(self):
        """Verify XChaCha ciphertext and tag match deterministic vector exactly."""
        import nacl.bindings

        # Use the repo-local toolset under the project root (parents[3]).
        base = Path(__file__).resolve()
        vectors_path = (
            base.parents[3] / "toolset" / "unified" / "crypto_test_vectors.json"
        )
        if not vectors_path.exists():
            pytest.skip(f"Deterministic vectors file not found: {vectors_path}")
        data = json.loads(vectors_path.read_text(encoding="utf-8"))
        vecs = data.get("deterministic_xaead_vectors", [])
        if not vecs:
            pytest.skip("No deterministic XAEAD vectors present")
        v = vecs[0]

        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"])
        aad = bytes.fromhex(v["aad"])
        pt = bytes.fromhex(v["plaintext"])

        combined = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            pt, aad, nonce, key
        )
        ct, tag = combined[:-16], combined[-16:]

        assert ct.hex() == v["ciphertext"], "XChaCha ciphertext mismatch"
        assert tag.hex() == v["tag"], "XChaCha tag mismatch"
