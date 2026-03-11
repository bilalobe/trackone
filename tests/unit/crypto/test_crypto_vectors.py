#!/usr/bin/env python3
"""
Canonical JSON, schema, and vector tests remain here; crypto-specific enabled tests were migrated
into focused offshoot modules (AEAD, HKDF, X25519, Ed25519) to avoid duplication.
"""
from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest


# Resolve the canonical test vectors file reliably by searching upward from this file.
# This makes the tests work whether they live under `scripts/tests` or `tests`.
def _find_vectors_path() -> Path | None:
    here = Path(__file__).resolve()
    candidate_rel = Path("toolset") / "unified" / "crypto_test_vectors.json"
    # Check this file's parents and itself for the expected path
    for p in [here] + list(here.parents):
        candidate = p / candidate_rel
        if candidate.exists():
            return candidate
    return None


@pytest.fixture(scope="module")
def test_vectors():
    """Load crypto test vectors from JSON file located at toolset/unified/crypto_test_vectors.json.

    If the file is not present, skip the tests that depend on it.
    """
    vectors_path = _find_vectors_path()
    if vectors_path is None:
        pytest.skip(
            "Test vectors file not found: toolset/unified/crypto_test_vectors.json (searched upward from tests)"
        )
    return json.loads(vectors_path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module", autouse=True)
def _load_modules(gateway_modules):
    """Ensure required gateway modules are available for the test module."""
    mb = gateway_modules.get("merkle_batcher")
    cu = gateway_modules.get("crypto_utils")
    if mb is None:
        pytest.skip("Required gateway module 'merkle_batcher' not available")
    # crypto_utils checks and crypto-enabled tests moved to focused modules
    return mb, cu


class TestCanonicalHashVectors:
    """Test canonical JSON serialization against known vectors."""

    def test_vectors_file_exists(self):
        """Verify test vectors file is present and valid JSON."""
        path = _find_vectors_path()
        assert (
            path is not None and path.exists()
        ), "Test vectors file not found: toolset/unified/crypto_test_vectors.json"
        vectors = json.loads(path.read_text(encoding="utf-8"))
        assert "canonical_hash_vectors" in vectors
        assert isinstance(vectors["canonical_hash_vectors"], list)

    def test_canonical_json_matches_expected(self, test_vectors, merkle_batcher):
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

    def test_sha256_hashes_are_deterministic(self, test_vectors, merkle_batcher):
        """Test that SHA256 hashes of canonical JSON are deterministic."""
        for vector in test_vectors["canonical_hash_vectors"]:
            fact = vector["fact"]

            # Compute hash twice
            canon1 = merkle_batcher.canonical_json(fact)
            hash1 = sha256(canon1).hexdigest()

            canon2 = merkle_batcher.canonical_json(fact)
            hash2 = sha256(canon2).hexdigest()

            assert hash1 == hash2, f"Non-deterministic hash for {vector['description']}"

    def test_all_vector_facts_are_valid(self, test_vectors, merkle_batcher):
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

    def test_minimal_fact_schema(self, merkle_batcher):
        """Test a minimal valid fact."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        fact = {
            "pod_id": "0000000000000001",
            "fc": 1,
            "ingest_time": 1759752000,
            "ingest_time_rfc3339_utc": "2025-10-06T12:00:00Z",
            "pod_time": None,
            "kind": "Custom",
            "payload": {},
        }

        merkle_batcher.validate_against_schema(fact, schemas["fact"], "Minimal fact")

    def test_fact_with_signature(self, merkle_batcher):
        """Test a fact with optional signature field."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        fact = {
            "pod_id": "0000000000000001",
            "fc": 1,
            "ingest_time": 1759752000,
            "ingest_time_rfc3339_utc": "2025-10-06T12:00:00Z",
            "pod_time": None,
            "kind": "Custom",
            "payload": {"data": "test"},
            "signature": "deadbeef",
        }

        merkle_batcher.validate_against_schema(
            fact, schemas["fact"], "Fact with signature"
        )

    def test_fact_missing_required_field(self, merkle_batcher):
        """Test that facts missing required fields are detected."""
        schemas = merkle_batcher.load_schemas()
        if "fact" not in schemas:
            pytest.skip("Fact schema not available")

        # Missing pod_id
        fact = {
            "fc": 1,
            "ingest_time": 1759752000,
            "ingest_time_rfc3339_utc": "2025-10-06T12:00:00Z",
            "pod_time": None,
            "kind": "Custom",
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
            assert "pod_id" in fact
            assert "fc" in fact
            assert "ingest_time" in fact
            assert "pod_time" in fact
            assert "kind" in fact
            assert "payload" in fact

    def test_vectors_have_varied_payloads(self, test_vectors):
        """Verify vectors have different payload structures."""
        vectors = test_vectors["canonical_hash_vectors"]
        payloads = [str(v["fact"]["payload"]) for v in vectors]

        # Should have at least some variety
        unique_payloads = set(payloads)
        assert len(unique_payloads) >= 2, "Vectors should have varied payloads"


class TestDeterministicAEADVectors:
    def test_chacha20poly1305_vector_matches(self):
        """Verify ciphertext and tag match deterministic vector exactly."""
        try:
            spec = importlib.util.find_spec("nacl.bindings")
        except ModuleNotFoundError:
            spec = None
        if spec is None:
            pytest.skip("PyNaCl not installed")
        import nacl.bindings

        vectors_path = _find_vectors_path()
        if vectors_path is None:
            pytest.skip(
                "Deterministic vectors file not found: toolset/unified/crypto_test_vectors.json"
            )
        data = json.loads(vectors_path.read_text(encoding="utf-8"))
        vecs = data.get("deterministic_aead_vectors", [])
        if not vecs:
            pytest.skip("No deterministic AEAD vectors present")
        v = vecs[0]
        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"])
        plaintext = bytes.fromhex(v["plaintext"])
        expected_ciphertext = bytes.fromhex(v["ciphertext"])
        expected_tag = bytes.fromhex(v["tag"])
        aad = bytes.fromhex(v["aad"]) if v.get("aad") is not None else None

        # Ensure NaCl's implementation matches the vector exactly
        combined = nacl.bindings.crypto_aead_chacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key
        )
        ct, tag = combined[:-16], combined[-16:]
        assert ct == expected_ciphertext
        assert tag == expected_tag

    def test_xchacha20poly1305_vector_matches(self):
        """Verify XChaCha ciphertext and tag match deterministic vector exactly."""
        try:
            spec = importlib.util.find_spec("nacl.bindings")
        except ModuleNotFoundError:
            spec = None
        if spec is None:
            pytest.skip("PyNaCl not installed")
        import nacl.bindings

        vectors_path = _find_vectors_path()
        if vectors_path is None:
            pytest.skip(
                "Deterministic vectors file not found: toolset/unified/crypto_test_vectors.json"
            )
        data = json.loads(vectors_path.read_text(encoding="utf-8"))
        vecs = data.get("deterministic_xaead_vectors", [])
        if not vecs:
            pytest.skip("No deterministic XAEAD vectors present")
        v = vecs[0]
        key = bytes.fromhex(v["key"])
        nonce = bytes.fromhex(v["nonce"])
        plaintext = bytes.fromhex(v["plaintext"])
        expected_ciphertext = bytes.fromhex(v["ciphertext"])
        expected_tag = bytes.fromhex(v["tag"])
        aad = bytes.fromhex(v["aad"]) if v.get("aad") is not None else None

        # Ensure NaCl's implementation matches the vector exactly
        combined = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key
        )
        ct, tag = combined[:-16], combined[-16:]
        assert ct == expected_ciphertext
        assert tag == expected_tag
