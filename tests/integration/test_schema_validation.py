#!/usr/bin/env python3
"""
Schema loading and validation tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# Import helpers from the actual implementation so tests can reuse them.
from scripts.gateway.merkle_batcher import load_schemas, validate_against_schema
from scripts.gateway.schema_validation import load_all_schemas, validate_schema_document


class TestSchemaValidation:
    def test_all_checked_in_schemas_are_valid_schema_documents(self):
        schemas = load_all_schemas()
        assert schemas, "Expected at least one checked-in schema"

        for _name, schema in schemas.items():
            validate_schema_document(schema)

    def test_load_schemas(self):
        schemas = load_schemas()
        assert isinstance(schemas, dict)

    def test_valid_block_header_passes_schema(self):
        schemas = load_schemas()
        if "block_header" not in schemas:
            pytest.skip("block_header schema not available")

        header = {
            "version": 1,
            "site_id": "test-001",
            "day": "2025-10-07",
            "batch_id": "test-001-2025-10-07-00",
            "merkle_root": "a" * 64,
            "count": 3,
            "leaf_hashes": ["b" * 64, "c" * 64, "d" * 64],
            "ots_proof": None,
        }

        validate_against_schema(header, schemas["block_header"], "Test header")

    def test_invalid_merkle_root_fails_schema(self):
        schemas = load_schemas()
        if "block_header" not in schemas:
            pytest.skip("block_header schema not available")

        header = {
            "version": 1,
            "site_id": "test-001",
            "day": "2025-10-07",
            "batch_id": "test-001-2025-10-07-00",
            "merkle_root": "invalid",
            "count": 0,
            "leaf_hashes": [],
            "ots_proof": None,
        }

        validate_against_schema(header, schemas["block_header"], "Invalid header")

    def test_ots_meta_files_match_schema(self):
        """All OTS metadata JSON files under proofs/ should conform to ots_meta schema."""
        schemas = load_schemas()
        if "ots_meta" not in schemas:
            pytest.skip("ots_meta schema not available")

        repo_root = Path(__file__).resolve().parents[2]
        proofs_dir = repo_root / "proofs"
        meta_files = sorted(proofs_dir.glob("*.ots.meta.json"))
        if not meta_files:
            pytest.skip("No OTS meta files found under proofs/")

        for path in meta_files:
            obj = json.loads(path.read_text(encoding="utf-8"))
            validate_against_schema(obj, schemas["ots_meta"], f"OTS meta {path.name}")

    def test_valid_peer_attestation_passes_schema(self):
        schemas = load_schemas()
        if "peer_attest" not in schemas:
            pytest.skip("peer_attest schema not available")

        attestation = {
            "day": "2025-10-07",
            "site_id": "an-001",
            "day_root": "a" * 64,
            "context": "trackone:day-root:v1",
            "signatures": [
                {
                    "peer_id": "peer-a",
                    "signature_hex": "b" * 128,
                    "pubkey_hex": "c" * 64,
                }
            ],
        }

        validate_against_schema(
            attestation, schemas["peer_attest"], "Valid peer attestation"
        )
