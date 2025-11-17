"""
Temporary directory and path fixtures for tests.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest


@pytest.fixture
def facts_dir(tmp_path: Path) -> Path:
    """Return a temporary facts directory."""
    d = tmp_path / "facts"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def out_dir(tmp_path: Path) -> Path:
    """Return a temporary output directory."""
    d = tmp_path / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def temp_workspace(tmp_path: Path) -> dict[str, Path]:
    """Return a comprehensive temporary workspace with subdirectories and schemas.

    Includes:
    - root, facts_dir, frames_dir, out_dir, device_table
    - schemas_dir (populated from toolset/unified/schemas if available)
    - day_dir, block_dir

    NOTE: For integration tests, use the module-scoped fixture in tests/integration/conftest.py
    """
    workspace = {
        "root": tmp_path / "workspace",
        "facts_dir": tmp_path / "workspace" / "facts",
        "frames_dir": tmp_path / "workspace" / "frames",
        "out_dir": tmp_path / "workspace" / "out",
        "device_table": tmp_path / "workspace" / "device_table.json",
        "schemas_dir": tmp_path / "workspace" / "schemas",
        "day_dir": tmp_path / "workspace" / "out" / "day",
        "block_dir": tmp_path / "workspace" / "out" / "block",
    }

    for _key, path in workspace.items():
        if isinstance(path, Path) and not path.suffix:
            path.mkdir(parents=True, exist_ok=True)

    schema_src = Path(__file__).parent.parent.parent / "toolset" / "unified" / "schemas"
    if schema_src.exists():
        for schema_file in schema_src.glob("*.schema.json"):
            shutil.copy(schema_file, workspace["schemas_dir"] / schema_file.name)

    return workspace


@pytest.fixture
def temp_dirs(tmp_path: Path) -> dict:
    """Return common temporary directory dict used by framed e2e tests.

    Keys:
    - `root`, `frames`, `facts`, `device_table`, `out_dir`

    Tests are free to mkdir the root themselves; this fixture only returns
    consistent paths so both security and ingest tests can share it.
    """
    root = tmp_path / "site_demo"
    frames = root / "frames.ndjson"
    facts = root / "facts"
    device_table = root / "device_table.json"
    out_dir = root
    return {
        "root": root,
        "frames": frames,
        "facts": facts,
        "device_table": device_table,
        "out_dir": out_dir,
    }
