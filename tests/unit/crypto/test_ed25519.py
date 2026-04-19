"""
Ed25519 digital signature tests.

Moved from test_crypto_impl.py so the "mother" file can be emptied; these are active tests.
"""

from __future__ import annotations

import pytest

pytest.importorskip("nacl")

import nacl.exceptions

from scripts.gateway import crypto_utils


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

    def test_signature_tampering_detected(self):
        """Test that signature tampering is detected."""
        kp = crypto_utils.ed25519_keypair()
        msg = b"important message"
        sig = crypto_utils.ed25519_sign(kp.private, msg)

        # Tamper with signature
        tampered_sig = bytes([sig[0] ^ 1]) + sig[1:]
        with pytest.raises(nacl.exceptions.BadSignatureError):
            crypto_utils.ed25519_verify(kp.public, msg, tampered_sig)

    def test_wrong_public_key_rejected(self):
        """Test that verification fails with wrong public key."""
        kp1 = crypto_utils.ed25519_keypair()
        kp2 = crypto_utils.ed25519_keypair()
        msg = b"message"

        sig = crypto_utils.ed25519_sign(kp1.private, msg)
        with pytest.raises(nacl.exceptions.BadSignatureError):
            crypto_utils.ed25519_verify(kp2.public, msg, sig)

    def test_empty_message_signing(self):
        """Test signing empty message."""
        kp = crypto_utils.ed25519_keypair()
        msg = b""

        sig = crypto_utils.ed25519_sign(kp.private, msg)
        crypto_utils.ed25519_verify(kp.public, msg, sig)
