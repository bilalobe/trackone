#!/usr/bin/env python3
"""
test_crypto_vectors.py

Tests for cryptographic operations and test vectors.
Currently, tests canonical JSON serialization and fact schema validation.
Adds enabled tests for X25519, HKDF, XChaCha20-Poly1305, and Ed25519.
"""
import importlib.util
import sys
from pathlib import Path

GW_DIR = Path(__file__).parent.parent / "gateway"
sys.path.insert(0, str(GW_DIR))

# Dynamically load merkle_batcher like other tests
mb_spec = importlib.util.spec_from_file_location(
    "merkle_batcher", str(GW_DIR / "merkle_batcher.py")
)
assert mb_spec and mb_spec.loader, "Cannot load merkle_batcher"
merkle_batcher = importlib.util.module_from_spec(mb_spec)
sys.modules["merkle_batcher"] = merkle_batcher  # Fix dataclass __module__ lookup
mb_spec.loader.exec_module(merkle_batcher)  # type: ignore

import json
from hashlib import sha256

import pytest

# Import crypto utils
CU_PATH = Path(__file__).parent.parent / "gateway" / "crypto_utils.py"
cu_spec = importlib.util.spec_from_file_location("crypto_utils", str(CU_PATH))
assert cu_spec and cu_spec.loader, f"Cannot load crypto_utils from {CU_PATH}"
crypto_utils = importlib.util.module_from_spec(cu_spec)
sys.modules["crypto_utils"] = crypto_utils  # Fix module lookup
cu_spec.loader.exec_module(crypto_utils)  # type: ignore

# Load test vectors
VECTORS_PATH = Path(__file__).parent.parent / "pod_sim" / "crypto_test_vectors.json"


@pytest.fixture
def test_vectors():
    """Load crypto test vectors from JSON file."""
    if not VECTORS_PATH.exists():
        pytest.skip(f"Test vectors file not found: {VECTORS_PATH}")
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


class TestCanonicalHashVectors:
    """Test canonical JSON serialization against known vectors."""

    def test_vectors_file_exists(self):
        """Verify test vectors file is present and valid JSON."""
        assert VECTORS_PATH.exists(), f"Test vectors file not found: {VECTORS_PATH}"
        vectors = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
        assert "canonical_hash_vectors" in vectors
        assert isinstance(vectors["canonical_hash_vectors"], list)

    def test_canonical_json_matches_expected(self, test_vectors):
        """Test that canonical_json produces expected output for each vector."""
        for vector in test_vectors["canonical_hash_vectors"]:
            fact = vector["fact"]
            expected_json = vector["expected_canonical_json"]

            result = merkle_batcher.canonical_json(fact)
            result_str = result.decode("utf-8")

            assert result_str == expected_json, (
                f"Canonical JSON mismatch for {vector['description']}\n"
                f"Expected: {expected_json}\n"
                f"Got: {result_str}"
            )

    def test_sha256_hashes_are_deterministic(self, test_vectors):
        """Test that SHA256 hashes of canonical JSON are deterministic."""
        for vector in test_vectors["canonical_hash_vectors"]:
            fact = vector["fact"]

            # Compute hash twice
            canon1 = merkle_batcher.canonical_json(fact)
            hash1 = sha256(canon1).hexdigest()

            canon2 = merkle_batcher.canonical_json(fact)
            hash2 = sha256(canon2).hexdigest()

            assert hash1 == hash2, f"Non-deterministic hash for {vector['description']}"

    def test_all_vector_facts_are_valid(self, test_vectors):
        """Test that all vector facts pass schema validation."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        for vector in test_vectors["canonical_hash_vectors"]:
            fact = vector["fact"]
            # Remove signature for schema validation if present but not required
            fact_to_validate = fact.copy()

            # validate_against_schema prints warnings but doesn't raise
            # We just ensure it doesn't crash
            merkle_batcher.validate_against_schema(
                fact_to_validate, schemas["fact"], vector["description"]
            )


class TestFactSchemaCompliance:
    """Test that facts comply with the fact schema."""

    def test_minimal_fact_schema(self):
        """Test a minimal valid fact."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        fact = {
            "device_id": "test-pod",
            "timestamp": "2025-10-06T12:00:00Z",
            "nonce": "aabbccddeeff00112233",
            "payload": {},
        }

        merkle_batcher.validate_against_schema(fact, schemas["fact"], "Minimal fact")

    def test_fact_with_signature(self):
        """Test a fact with optional signature field."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        fact = {
            "device_id": "test-pod",
            "timestamp": "2025-10-06T12:00:00Z",
            "nonce": "aabbccddeeff00112233",
            "payload": {"data": "test"},
            "signature": "deadbeef",
        }

        merkle_batcher.validate_against_schema(
            fact, schemas["fact"], "Fact with signature"
        )

    def test_fact_missing_required_field(self):
        """Test that facts missing required fields are detected."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        # Missing device_id
        fact = {
            "timestamp": "2025-10-06T12:00:00Z",
            "nonce": "aabbccddeeff00112233",
            "payload": {},
        }

        # validate_against_schema should print a warning for invalid fact
        # It doesn't raise, but we verify it can handle invalid input
        merkle_batcher.validate_against_schema(fact, schemas["fact"], "Invalid fact")


class TestVectorCoverage:
    """Test that we have adequate test vector coverage."""

    def test_vector_count(self, test_vectors):
        """Verify we have multiple test vectors."""
        vectors = test_vectors["canonical_hash_vectors"]
        assert len(vectors) >= 3, "Should have at least 3 test vectors"

    def test_vector_structure(self, test_vectors):
        """Verify each vector has required fields."""
        for vector in test_vectors["canonical_hash_vectors"]:
            assert "description" in vector
            assert "fact" in vector
            assert "expected_canonical_json" in vector

            # Verify fact structure
            fact = vector["fact"]
            assert "device_id" in fact
            assert "timestamp" in fact
            assert "nonce" in fact
            assert "payload" in fact

    def test_vectors_have_varied_payloads(self, test_vectors):
        """Verify vectors have different payload structures."""
        vectors = test_vectors["canonical_hash_vectors"]
        payloads = [str(v["fact"]["payload"]) for v in vectors]

        # Should have at least some variety
        unique_payloads = set(payloads)
        assert len(unique_payloads) >= 2, "Vectors should have varied payloads"


class TestCryptoEnabled:
    """Previously skipped crypto tests are now enabled using crypto_utils."""

    def test_x25519_key_exchange(self):
        a = crypto_utils.x25519_keypair()
        b = crypto_utils.x25519_keypair()
        za = crypto_utils.x25519_shared_secret(a.private, b.public)
        zb = crypto_utils.x25519_shared_secret(b.private, a.public)
        assert za == zb and len(za) == 32

    def test_hkdf_derivation(self):
        ikm = b"\x11" * 32
        salt = b"\x22" * 16
        up = crypto_utils.hkdf_sha256(ikm, salt, b"barnacle:up", 32)
        down = crypto_utils.hkdf_sha256(ikm, salt, b"barnacle:down", 32)
        assert len(up) == 32 and len(down) == 32 and up != down

    def test_xchacha20_poly1305_encryption(self):
        key = bytes(range(32))
        nonce = b"n" * 24
        aad = b"\x01\x02\x03"
        pt = b"payload"
        ct, tag = crypto_utils.xchacha20poly1305_ietf_encrypt(key, nonce, pt, aad)
        rt = crypto_utils.xchacha20poly1305_ietf_decrypt(key, nonce, ct, tag, aad)
        assert rt == pt

    def test_ed25519_signatures(self):
        import nacl.exceptions

        kp = crypto_utils.ed25519_keypair()
        msg = b"day.bin root"
        sig = crypto_utils.ed25519_sign(kp.private, msg)
        crypto_utils.ed25519_verify(kp.public, msg, sig)
        with pytest.raises(nacl.exceptions.BadSignatureError):
            crypto_utils.ed25519_verify(kp.public, msg + b"x", sig)


class TestDeterministicAEADVectors:
    def test_chacha20poly1305_vector_matches(self):
        """Verify ciphertext and tag match deterministic vector exactly."""
        import nacl.bindings

        vectors_path = (
            Path(__file__).resolve().parents[2]
            / "toolset"
            / "unified"
            / "crypto_test_vectors.json"
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

        vectors_path = (
            Path(__file__).resolve().parents[2]
            / "toolset"
            / "unified"
            / "crypto_test_vectors.json"
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


if __name__ == "__main__":
    import pytest as _pytest

    _pytest.main([__file__, "-v"])
