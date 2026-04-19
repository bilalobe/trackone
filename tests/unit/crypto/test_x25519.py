"""
X25519 key exchange tests.

Tests for X25519 Elliptic Curve Diffie-Hellman key agreement.
"""

from __future__ import annotations

import pytest

pytest.importorskip("nacl")

from scripts.gateway import crypto_utils


class TestX25519:
    """Test X25519 key exchange functionality."""

    def test_key_generation(self):
        """Test X25519 key pair generation."""
        kp = crypto_utils.x25519_keypair()
        assert kp.private is not None
        assert kp.public is not None

    def test_shared_secret_agreement(self):
        """Test that both parties compute the same shared secret."""
        alice = crypto_utils.x25519_keypair()
        bob = crypto_utils.x25519_keypair()

        shared_a = crypto_utils.x25519_shared_secret(alice.private, bob.public)
        shared_b = crypto_utils.x25519_shared_secret(bob.private, alice.public)

        assert shared_a == shared_b
        assert len(shared_a) == 32

    def test_different_key_pairs_produce_different_secrets(self):
        """Test that different key pairs produce different shared secrets."""
        alice = crypto_utils.x25519_keypair()
        bob = crypto_utils.x25519_keypair()
        charlie = crypto_utils.x25519_keypair()

        shared_ab = crypto_utils.x25519_shared_secret(alice.private, bob.public)
        shared_ac = crypto_utils.x25519_shared_secret(alice.private, charlie.public)

        assert shared_ab != shared_ac
