#!/usr/bin/env python3
"""
Frame verifier schema-loading edge cases (moved from test_unit_coverage_boost.py)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.gateway import frame_verifier


class TestFrameVerifierSchemaEdgeCases:
    """Test frame_verifier schema loading edge cases."""

    def test_load_schema_exception_during_read(self, tmp_path):
        """Test load_schema_from_path when file.exists() is True but read raises OSError."""
        schema_path = tmp_path / "schema.json"
        schema_path.write_text('{"test": "data"}', encoding="utf-8")

        # Mock exists to return True but read_text to raise exception
        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "read_text", side_effect=OSError("Disk error")),
        ):
            with pytest.raises(OSError, match="Disk error"):
                frame_verifier.load_schema_from_path(schema_path)

    def test_load_schema_valid_file(self, tmp_path):
        """Test load_schema_from_path with a valid schema file."""
        schema_path = tmp_path / "valid.schema.json"
        schema_path.write_text(
            json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema"}),
            encoding="utf-8",
        )
        result = frame_verifier.load_schema_from_path(schema_path)
        assert result is not None
        assert result["$schema"] == "https://json-schema.org/draft/2020-12/schema"
