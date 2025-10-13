#!/usr/bin/env python3
"""
crypto_utils.py

Reusable cryptographic helpers used in tests and future pipeline stages.
Implements all primitives using PyNaCl (libsodium) for consistency and performance.

Primitives:
- X25519 key exchange (ephemeral ECDH)
- HKDF-SHA256 (RFC 5869, HMAC-SHA256)
- ChaCha20-Poly1305 (96-bit nonce) AEAD
- XChaCha20-Poly1305 (192-bit nonce) AEAD
- Ed25519 sign/verify

Migration from cryptography to PyNaCl completed 2025-10-12 (see ADR-005).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

import nacl.bindings
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils

# --- X25519 ---


@dataclass
class X25519Keypair:
    private: nacl.public.PrivateKey
    public: nacl.public.PublicKey


def x25519_keypair() -> X25519Keypair:
    """Generate X25519 key pair for ECDH."""
    priv = nacl.public.PrivateKey.generate()
    pub = priv.public_key
    return X25519Keypair(private=priv, public=pub)


def x25519_shared_secret(
    priv: nacl.public.PrivateKey, peer_pub: nacl.public.PublicKey
) -> bytes:
    """Compute X25519 shared secret."""
    box = nacl.public.Box(priv, peer_pub)
    # Return raw shared secret (libsodium does the scalar multiplication)
    return bytes(box.shared_key())


# --- HKDF (SHA-256, RFC 5869) ---


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF (RFC 5869) with HMAC-SHA256.

    Args:
        ikm: input key material
        salt: optional salt (can be empty)
        info: context/application specific info (can be empty)
        length: length of output keying material in bytes
    Returns:
        OKM of requested length.
    """
    if salt is None:
        salt = b""
    if info is None:
        info = b""

    # HKDF-Extract
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # HKDF-Expand
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


# --- ChaCha20-Poly1305 (96-bit nonce) ---


def chacha20poly1305_encrypt(
    key: bytes, nonce96: bytes, plaintext: bytes, aad: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    Encrypt with ChaCha20-Poly1305 (96-bit nonce, IETF variant).

    Returns:
        (ciphertext, tag) tuple
    """
    aad_b = aad if aad is not None else b""
    combined = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
        plaintext, aad_b, nonce96, key
    )
    # Combined format: ciphertext || tag (16 bytes)
    return combined[:-16], combined[-16:]


def chacha20poly1305_decrypt(
    key: bytes, nonce96: bytes, ciphertext: bytes, tag: bytes, aad: bytes | None = None
) -> bytes:
    """
    Decrypt with ChaCha20-Poly1305 (96-bit nonce, IETF variant).

    Raises:
        nacl.exceptions.CryptoError: If authentication fails
    """
    aad_b = aad if aad is not None else b""
    return nacl.bindings.crypto_aead_chacha20poly1305_ietf_decrypt(
        ciphertext + tag, aad_b, nonce96, key
    )


# --- XChaCha20-Poly1305 (192-bit nonce) ---


def xchacha20poly1305_ietf_encrypt(
    key: bytes, nonce192: bytes, plaintext: bytes, aad: bytes | None = None
) -> tuple[bytes, bytes]:
    """
    Encrypt with XChaCha20-Poly1305 (192-bit nonce).

    Returns:
        (ciphertext, tag) tuple
    """
    aad_b = aad if aad is not None else b""
    combined = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad_b, nonce192, key
    )
    return combined[:-16], combined[-16:]


def xchacha20poly1305_ietf_decrypt(
    key: bytes, nonce192: bytes, ciphertext: bytes, tag: bytes, aad: bytes | None = None
) -> bytes:
    """
    Decrypt with XChaCha20-Poly1305 (192-bit nonce).

    Raises:
        nacl.exceptions.CryptoError: If authentication fails
    """
    aad_b = aad if aad is not None else b""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext + tag, aad_b, nonce192, key
    )


# --- Ed25519 ---


@dataclass
class Ed25519Keypair:
    private: nacl.signing.SigningKey
    public: nacl.signing.VerifyKey


def ed25519_keypair() -> Ed25519Keypair:
    """Generate Ed25519 signing key pair."""
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    return Ed25519Keypair(private=signing_key, public=verify_key)


def ed25519_sign(priv: nacl.signing.SigningKey, message: bytes) -> bytes:
    """Sign message with Ed25519."""
    signed = priv.sign(message)
    # Return just the signature (first 64 bytes), not the signed message
    return signed.signature


def ed25519_verify(
    pub: nacl.signing.VerifyKey, message: bytes, signature: bytes
) -> None:
    """
    Verify Ed25519 signature.

    Raises:
        nacl.exceptions.BadSignatureError: If signature is invalid
    """
    pub.verify(message, signature)
