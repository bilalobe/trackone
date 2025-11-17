#!/usr/bin/env python3
"""
Shared helpers / fixtures for integration tests under scripts/tests/integration.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest


@pytest.fixture
def temp_workspace(tmp_path):
    """Create a temporary workspace with facts, schemas, and output directories.

    Copies available schemas from toolset/unified/schemas if present.
    Returns a dict with 'facts_dir', 'out_dir', 'schemas_dir'.
    """
    workspace = {
        "facts_dir": tmp_path / "facts",
        "out_dir": tmp_path / "out",
        "schemas_dir": tmp_path / "schemas",
    }
    workspace["facts_dir"].mkdir()
    workspace["out_dir"].mkdir()
    workspace["schemas_dir"].mkdir()

    # Copy schemas from toolset/unified/schemas (if present)
    schema_src = Path(__file__).resolve().parents[4] / "toolset" / "unified" / "schemas"
    for schema_file in [
        "fact.schema.json",
        "block_header.schema.json",
        "day_record.schema.json",
    ]:
        src = schema_src / schema_file
        if src.exists():
            shutil.copy(src, workspace["schemas_dir"] / schema_file)

    return workspace
