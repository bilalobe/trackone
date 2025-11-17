#!/usr/bin/env python3
"""
Canonical JSON edge case tests (moved from test_edge_cases.py)
"""
from __future__ import annotations

import json

import pytest


@pytest.fixture(scope="module", autouse=True)
def _load_modules(gateway_modules):
    merkle_batcher = gateway_modules.get("merkle_batcher")
    if merkle_batcher is None:
        pytest.skip("Required gateway module 'merkle_batcher' not available")
    return merkle_batcher


class TestCanonicalJsonEdgeCases:
    """Test edge cases for canonical JSON."""

    @pytest.mark.parametrize(
        "obj,expected",
        [
            ({"a": 1}, b'{"a":1}'),
            ({"z": 1, "a": 2}, b'{"a":2,"z":1}'),
            ({}, b"{}"),
            ({"key": ""}, b'{"key":""}'),
            ({"key": None}, b'{"key":null}'),
        ],
    )
    def test_canonical_json_parametrized(self, merkle_batcher, obj, expected):
        result = merkle_batcher.canonical_json(obj)
        assert result == expected

    def test_canonical_json_with_special_characters(self, merkle_batcher):
        obj = {"key": 'value with "quotes" and \n newlines'}
        result = merkle_batcher.canonical_json(obj)

        # Should be valid JSON
        assert isinstance(result, bytes | bytearray)
        # Should be parseable
        parsed = json.loads(result)
        assert parsed == obj

    def test_canonical_json_with_arrays(self, merkle_batcher):
        obj = {"array": [3, 1, 2], "key": "value"}
        result = merkle_batcher.canonical_json(obj)

        parsed = json.loads(result)
        assert parsed["array"] == [3, 1, 2]  # Order preserved
