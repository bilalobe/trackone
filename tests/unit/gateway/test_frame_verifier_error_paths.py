#!/usr/bin/env python3
"""
Error-path tests for frame_verifier (moved from test_unit_coverage_boost.py)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from scripts.gateway import frame_verifier


class TestFrameVerifierErrorPaths:
    """Test error paths in frame_verifier.py to cover lines 42-44, 53-56."""

    def test_load_schema_nonexistent_file(self, tmp_path):
        """Test load_schema with non-existent file."""
        schema_path = tmp_path / "nonexistent_schema.json"
        result = frame_verifier.load_schema(schema_path)
        assert result is None

    def test_load_schema_invalid_json(self, tmp_path):
        """Test load_schema with invalid JSON content."""
        schema_path = tmp_path / "invalid_schema.json"
        schema_path.write_text("{ invalid json }", encoding="utf-8")
        result = frame_verifier.load_schema(schema_path)
        assert result is None

    def test_load_schema_non_dict_content(self, tmp_path):
        """Test load_schema when JSON is valid but not a dict."""
        schema_path = tmp_path / "array_schema.json"
        schema_path.write_text('["array", "not", "dict"]', encoding="utf-8")
        result = frame_verifier.load_schema(schema_path)
        assert result is None

    def test_load_schema_read_permission_error(self, tmp_path):
        """Test load_schema when file cannot be read (permission error)."""
        schema_path = tmp_path / "unreadable_schema.json"
        schema_path.write_text('{"valid": "json"}', encoding="utf-8")

        # Mock Path.read_text to raise PermissionError
        with patch.object(
            Path, "read_text", side_effect=PermissionError("Access denied")
        ):
            result = frame_verifier.load_schema(schema_path)
            assert result is None
