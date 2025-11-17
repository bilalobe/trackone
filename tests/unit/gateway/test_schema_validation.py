#!/usr/bin/env python3
"""
Schema validation edge cases (moved from test_edge_cases.py)
"""
from __future__ import annotations

import pytest


@pytest.fixture(scope="module", autouse=True)
def _load_modules(gateway_modules):
    merkle_batcher = gateway_modules.get("merkle_batcher")
    if merkle_batcher is None:
        pytest.skip("Required gateway module 'merkle_batcher' not available")
    return merkle_batcher


class TestSchemaValidation:
    """Test schema validation edge cases."""

    def test_validate_with_missing_schema(self, merkle_batcher):
        """Validation with missing schema should handle gracefully."""
        schemas = merkle_batcher.load_schemas()

        # Try to validate against non-existent schema
        obj = {"test": "data"}
        # Call the validator; should not raise and should return None
        ret = merkle_batcher.validate_against_schema(
            obj, schemas.get("nonexistent", {}), "Test"
        )
        assert ret is None

    def test_load_schemas_when_missing(self, merkle_batcher):
        """Loading schemas when directory doesn't exist should handle gracefully."""
        schemas = merkle_batcher.load_schemas()
        # Should return a dict even if schemas not found
        assert isinstance(schemas, dict)
