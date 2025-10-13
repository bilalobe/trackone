#!/usr/bin/env python3
"""
Comprehensive crypto implementation tests for TrackOne:
- X25519 key exchange (shared secret equality)
- HKDF-SHA256 derivation (stability and domain separation)
- ChaCha20-Poly1305 AEAD (96-bit nonce) round-trip and tamper resistance
- XChaCha20-Poly1305 AEAD (192-bit nonce) round-trip and tamper resistance
- Ed25519 signing/verification and tamper resistance

These tests expand coverage to replace the previously skipped placeholders.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Import from scripts/gateway
GW_DIR = Path(__file__).parent.parent / "gateway"
cu_spec = importlib.util.spec_from_file_location(
    "crypto_utils", str(GW_DIR / "crypto_utils.py")
)
assert cu_spec and cu_spec.loader
crypto_utils = importlib.util.module_from_spec(cu_spec)
sys.modules["crypto_utils"] = crypto_utils
cu_spec.loader.exec_module(crypto_utils)  # type: ignore

import nacl.exceptions


class TestX25519:
    def test_key_generation(self):
        """Test X25519 key pair generation."""
        kp = crypto_utils.x25519_keypair()
        assert kp.private is not None
        assert kp.public is not None

    def test_shared_secret_agreement(self):
        """Test that both parties compute same shared secret."""
        alice = crypto_utils.x25519_keypair()
        bob = crypto_utils.x25519_keypair()

        shared_a = crypto_utils.x25519_shared_secret(alice.private, bob.public)
        shared_b = crypto_utils.x25519_shared_secret(bob.private, alice.public)

        assert shared_a == shared_b
        assert len(shared_a) == 32


class TestHKDF:
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


class TestChaCha20Poly1305:
    def test_encrypt_decrypt_round_trip(self):
        """Test ChaCha20-Poly1305 encryption and decryption."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        aad = b"additional_data"
        plaintext = b"secret message"

        ct, tag = crypto_utils.chacha20poly1305_encrypt(key, nonce, plaintext, aad)
        recovered = crypto_utils.chacha20poly1305_decrypt(key, nonce, ct, tag, aad)

        assert recovered == plaintext

    def test_authentication_failure_detection(self):
        """Test that tampering is detected."""
        key = bytes(range(32))
        nonce = b"\x00" * 12
        aad = b"aad"
        pt = b"data"

        ct, tag = crypto_utils.chacha20poly1305_encrypt(key, nonce, pt, aad)

        # Tamper ciphertext
        ct_bad = bytes([ct[0] ^ 1]) + ct[1:]
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.chacha20poly1305_decrypt(key, nonce, ct_bad, tag, aad)
        # Tamper tag
        tag_bad = bytes([tag[0] ^ 1]) + tag[1:]
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.chacha20poly1305_decrypt(key, nonce, ct, tag_bad, aad)
        # Tamper AAD
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.chacha20poly1305_decrypt(key, nonce, ct, tag, aad + b"X")


class TestXChaCha20Poly1305:
    def test_encrypt_decrypt_round_trip(self):
        """Test XChaCha20-Poly1305 with 192-bit nonce."""
        key = bytes(range(32))
        nonce = b"N" * 24
        aad = b"\x01\x02\x03"
        pt = b"payload_data"

        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(key, nonce, pt, aad)
        rt = crypto_utils.xchacha20poly1305_ietf_decrypt(key, nonce, ct, tag, aad)

        assert rt == pt
        # Tamper
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.xchacha20poly1305_ietf_decrypt(
                key, nonce, bytes([ct[0] ^ 2]) + ct[1:], tag, aad
            )
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.xchacha20poly1305_ietf_decrypt(
                key, nonce, ct, bytes([tag[0] ^ 2]) + tag[1:], aad
            )
        with pytest.raises(nacl.exceptions.CryptoError):
            crypto_utils.xchacha20poly1305_ietf_decrypt(key, nonce, ct, tag, aad + b"X")


class TestEd25519:
    def test_sign_and_verify(self):
        """Test Ed25519 signature generation and verification."""
        kp = crypto_utils.ed25519_keypair()
        msg = b"message to sign"

        sig = crypto_utils.ed25519_sign(kp.private, msg)
        crypto_utils.ed25519_verify(kp.public, msg, sig)
        # Tamper
        with pytest.raises(nacl.exceptions.BadSignatureError):
            crypto_utils.ed25519_verify(kp.public, msg + b"!", sig)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
