#!/usr/bin/env python3
"""
Frame verifier schema-loading edge cases (moved from test_unit_coverage_boost.py)
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from scripts.gateway import frame_verifier


class TestFrameVerifierSchemaEdgeCases:
    """Test frame_verifier schema loading edge cases."""

    def test_load_schema_exception_during_read(self, tmp_path):
        """Test _load_schema when file.exists() is True but read raises exception."""
        schema_path = tmp_path / "schema.json"
        schema_path.write_text('{"test": "data"}', encoding="utf-8")

        # Mock exists to return True but read_text to raise exception
        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(Path, "read_text", side_effect=OSError("Disk error")),
        ):
            result = frame_verifier._load_schema(schema_path)
            assert result is None
