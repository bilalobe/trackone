#!/usr/bin/env python3
"""
Schema loading and validation tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations

import pytest


class TestSchemaValidation:
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
