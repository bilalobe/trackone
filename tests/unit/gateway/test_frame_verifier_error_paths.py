#!/usr/bin/env python3
"""
Error-path tests for frame_verifier (moved from test_unit_coverage_boost.py)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.gateway import frame_verifier


class TestFrameVerifierErrorPaths:
    """Test error paths in frame_verifier.load_schema_from_path."""

    def test_load_schema_nonexistent_file(self, tmp_path):
        """Test load_schema_from_path with non-existent file returns None."""
        schema_path = tmp_path / "nonexistent_schema.json"
        result = frame_verifier.load_schema_from_path(schema_path)
        assert result is None

    def test_load_schema_invalid_json(self, tmp_path):
        """Test load_schema_from_path raises JSONDecodeError on invalid JSON content."""
        schema_path = tmp_path / "invalid_schema.json"
        schema_path.write_text("{ invalid json }", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            frame_verifier.load_schema_from_path(schema_path)

    def test_load_schema_non_dict_content(self, tmp_path):
        """Test load_schema_from_path raises ValueError when JSON root is not a dict."""
        schema_path = tmp_path / "array_schema.json"
        schema_path.write_text('["array", "not", "dict"]', encoding="utf-8")
        with pytest.raises(ValueError, match="must be a JSON object"):
            frame_verifier.load_schema_from_path(schema_path)

    def test_load_schema_read_permission_error(self, tmp_path):
        """Test load_schema_from_path raises PermissionError when file cannot be read."""
        schema_path = tmp_path / "unreadable_schema.json"
        schema_path.write_text('{"valid": "json"}', encoding="utf-8")

        with patch.object(
            Path, "read_text", side_effect=PermissionError("Access denied")
        ):
            with pytest.raises(PermissionError, match="Access denied"):
                frame_verifier.load_schema_from_path(schema_path)
