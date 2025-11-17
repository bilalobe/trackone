#!/usr/bin/env python3
"""
Canonical JSON tests extracted from test_gateway_pipeline.py
"""
from __future__ import annotations


class TestCanonicalJson:
    def test_canonical_json_sorted_keys(self):
        obj = {"z": 1, "a": 2, "m": 3}
        # canonical_json is provided as a module-level global by the test conftest
        result = canonical_json(obj)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_canonical_json_no_whitespace(self):
        obj = {"key": "value"}
        result = canonical_json(obj)
        assert b" " not in result
        assert b"\n" not in result

    def test_canonical_json_deterministic(self):
        obj = {"nested": {"b": 2, "a": 1}, "top": "value"}
        result1 = canonical_json(obj)
        result2 = canonical_json(obj)
        assert result1 == result2
