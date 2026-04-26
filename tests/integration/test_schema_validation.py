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
from scripts.gateway.schema_validation import (
    SCHEMA_VALIDATION_EXCEPTIONS,
    load_all_schemas,
    load_schema,
    validate_instance,
    validate_schema_document,
)
from trackone_core.admission import (
    REJECTION_REASON_TAXONOMY,
    REJECTION_SOURCE_TAXONOMY,
)


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
        """Checked-in OTS metadata sidecars should conform to ots_meta schema."""
        schemas = load_schemas()
        if "ots_meta" not in schemas:
            pytest.skip("ots_meta schema not available")

        repo_root = Path(__file__).resolve().parents[2]
        meta_dir = repo_root / "out" / "site_demo" / "day"
        meta_files = sorted(meta_dir.glob("*.ots.meta.json"))
        if not meta_files:
            pytest.skip("No checked-in OTS meta files found under out/site_demo/day/")

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

    def test_scitt_statement_examples_match_schema(self):
        schemas = load_all_schemas()
        if (
            "scitt_verify_manifest_statement" not in schemas
            or "scitt_evidence_bundle_statement" not in schemas
        ):
            pytest.skip("SCITT statement schemas not available")

        repo_root = Path(__file__).resolve().parents[2]
        examples_dir = repo_root / "toolset" / "unified" / "examples"
        verify_example = json.loads(
            (examples_dir / "scitt_verify_manifest_statement.json").read_text(
                encoding="utf-8"
            )
        )
        bundle_example = json.loads(
            (examples_dir / "scitt_evidence_bundle_statement.json").read_text(
                encoding="utf-8"
            )
        )

        validate_against_schema(
            verify_example,
            schemas["scitt_verify_manifest_statement"],
            "SCITT verify-manifest statement example",
        )
        validate_against_schema(
            bundle_example,
            schemas["scitt_evidence_bundle_statement"],
            "SCITT evidence-bundle statement example",
        )

    def test_commitment_vector_corpus_matches_public_schemas(self):
        repo_root = Path(__file__).resolve().parents[2]
        vector_dir = repo_root / "toolset" / "vectors" / "trackone-canonical-cbor-v1"
        manifest_schema = load_schema("commitment_vector_manifest")
        fact_schema = load_schema("commitment_fact_projection")
        assert manifest_schema is not None
        assert fact_schema is not None

        manifest = json.loads((vector_dir / "manifest.json").read_text("utf-8"))
        validate_instance(manifest, manifest_schema)

        for entry in manifest["facts"]:
            fact = json.loads((vector_dir / entry["json_path"]).read_text("utf-8"))
            validate_instance(fact, fact_schema)

    def test_verify_manifest_contract_rejects_nonportable_artifact_paths(self):
        schema = load_schema("verify_manifest")
        assert schema is not None
        digest = "a" * 64

        manifest = {
            "version": 1,
            "date": "2026-04-25",
            "site": "site-a",
            "device_id": "pod-001",
            "frame_count": 1,
            "facts_dir": "facts",
            "artifacts": {
                "block": {"path": "blocks/2026-04-25-00.block.json", "sha256": digest},
                "day_cbor": {"path": "day/2026-04-25.cbor", "sha256": digest},
                "day_json": {"path": "day/2026-04-25.json", "sha256": digest},
                "day_sha256": {"path": "day/2026-04-25.sha256", "sha256": digest},
                "provisioning_input": {
                    "path": "provisioning/authoritative-input.json",
                    "sha256": digest,
                },
                "provisioning_records": {
                    "path": "provisioning/records.json",
                    "sha256": digest,
                },
                "sensorthings_projection": {
                    "path": "sensorthings/projection.json",
                    "sha256": digest,
                },
            },
            "anchoring": {},
            "verification_bundle": {
                "disclosure_class": "A",
                "commitment_profile_id": "trackone-canonical-cbor-v1",
                "checks_executed": ["verification_manifest_validation"],
                "checks_skipped": [],
            },
        }

        validate_instance(manifest, schema)

        manifest["artifacts"]["day_cbor"]["path"] = "/tmp/2026-04-25.cbor"
        with pytest.raises(SCHEMA_VALIDATION_EXCEPTIONS):
            validate_instance(manifest, schema)

    def test_rejection_audit_schema_matches_operator_taxonomy(self):
        schema = load_schema("rejection_audit")
        assert schema is not None
        assert (
            tuple(schema["properties"]["reason"]["enum"]) == REJECTION_REASON_TAXONOMY
        )
        assert (
            tuple(schema["properties"]["source"]["enum"]) == REJECTION_SOURCE_TAXONOMY
        )

        record = {
            "device_id": "pod-001",
            "fc": 7,
            "reason": "duplicate",
            "observed_at_utc": "2026-04-25T12:00:00+00:00",
            "frame_sha256": "a" * 64,
            "source": "replay",
        }
        validate_instance(record, schema)

        record["reason"] = "operator-note"
        with pytest.raises(SCHEMA_VALIDATION_EXCEPTIONS):
            validate_instance(record, schema)
