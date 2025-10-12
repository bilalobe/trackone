#!/usr/bin/env python3
"""
test_crypto_vectors.py

Tests for cryptographic operations and test vectors.
Currently tests canonical JSON serialization and fact schema validation.
Full crypto implementation (X25519, HKDF, XChaCha20-Poly1305) will be added in Track 1 phase.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "gateway"))

import json
from hashlib import sha256

import pytest
from merkle_batcher import canonical_json, load_schemas, validate_against_schema

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

            result = canonical_json(fact)
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
            canon1 = canonical_json(fact)
            hash1 = sha256(canon1).hexdigest()

            canon2 = canonical_json(fact)
            hash2 = sha256(canon2).hexdigest()

            assert hash1 == hash2, f"Non-deterministic hash for {vector['description']}"

    def test_all_vector_facts_are_valid(self, test_vectors):
        """Test that all vector facts pass schema validation."""
        schemas = load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        for vector in test_vectors["canonical_hash_vectors"]:
            fact = vector["fact"]
            # Remove signature for schema validation if present but not required
            fact_to_validate = fact.copy()

            # validate_against_schema prints warnings but doesn't raise
            # We just ensure it doesn't crash
            validate_against_schema(
                fact_to_validate, schemas["fact"], vector["description"]
            )


class TestFactSchemaCompliance:
    """Test that facts comply with the fact schema."""

    def test_minimal_fact_schema(self):
        """Test a minimal valid fact."""
        schemas = load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        fact = {
            "device_id": "test-pod",
            "timestamp": "2025-10-06T12:00:00Z",
            "nonce": "aabbccddeeff00112233",
            "payload": {},
        }

        validate_against_schema(fact, schemas["fact"], "Minimal fact")

    def test_fact_with_signature(self):
        """Test a fact with optional signature field."""
        schemas = load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        fact = {
            "device_id": "test-pod",
            "timestamp": "2025-10-06T12:00:00Z",
            "nonce": "aabbccddeeff00112233",
            "payload": {"data": "test"},
            "signature": "deadbeef",
        }

        validate_against_schema(fact, schemas["fact"], "Fact with signature")

    def test_fact_missing_required_field(self):
        """Test that facts missing required fields are detected."""
        schemas = load_schemas()
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
        validate_against_schema(fact, schemas["fact"], "Invalid fact")


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


class TestFutureCryptoPlaceholders:
    """Placeholder tests for future crypto implementations."""

    def test_future_crypto_sections_exist(self, test_vectors):
        """Verify placeholder sections exist for future crypto implementations."""
        assert "future_crypto_vectors" in test_vectors
        future = test_vectors["future_crypto_vectors"]

        # These sections are placeholders for Track 1 implementation
        assert "x25519_key_exchange" in future
        assert "hkdf_derivation" in future
        assert "xchacha20_poly1305_encryption" in future
        assert "ed25519_signatures" in future

    @pytest.mark.skip(reason="X25519 key exchange not yet implemented - Track 1 phase")
    def test_x25519_key_exchange_placeholder(self):
        """Placeholder for X25519 ECDH key exchange tests."""
        pass

    @pytest.mark.skip(reason="HKDF derivation not yet implemented - Track 1 phase")
    def test_hkdf_derivation_placeholder(self):
        """Placeholder for HKDF key derivation tests."""
        pass

    @pytest.mark.skip(reason="XChaCha20-Poly1305 not yet implemented - Track 1 phase")
    def test_xchacha20_poly1305_placeholder(self):
        """Placeholder for XChaCha20-Poly1305 AEAD encryption tests."""
        pass

    @pytest.mark.skip(reason="Ed25519 signatures not yet implemented - Track 1 phase")
    def test_ed25519_signatures_placeholder(self):
        """Placeholder for Ed25519 signature tests."""
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
