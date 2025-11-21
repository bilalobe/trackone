"""
Integration test fixtures (module-scoped).

These fixtures are specific to integration tests that span multiple modules.

Note: Gateway module loaders, file I/O helpers, and pipeline runners are now
centralized in tests/fixtures/ and auto-imported. This file contains only
integration-test-specific overrides and helpers.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

# ============================================================================
# Integration-specific workspace fixture
# ============================================================================


@pytest.fixture(scope="module")
def temp_workspace(tmp_path_factory) -> dict[str, Path]:
    """Return a comprehensive temporary workspace with subdirectories and schemas (module-scoped).

    Shared across all tests in the integration module to reduce setup overhead.
    However, facts_dir and out_dir are cleared before each test to prevent state contamination.

    Includes:
    - root, facts_dir, frames_dir, out_dir, device_table
    - schemas_dir (populated from toolset/unified/schemas if available)
    - day_dir, block_dir
    """
    tmp_path = tmp_path_factory.mktemp("integration_workspace")
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

    yield workspace

    # Cleanup: clear facts_dir and out_dir after the module finishes
    if workspace["facts_dir"].exists():
        shutil.rmtree(workspace["facts_dir"])
    if workspace["out_dir"].exists():
        shutil.rmtree(workspace["out_dir"])


@pytest.fixture(autouse=True)
def _reset_temp_workspace_per_test(temp_workspace):
    """Auto-use fixture to reset temp_workspace directories before each test.

    This prevents state contamination between tests while keeping the module-scoped
    fixture to share schemas and other setup.
    """
    # Reset facts_dir and out_dir before each test
    if temp_workspace["facts_dir"].exists():
        shutil.rmtree(temp_workspace["facts_dir"])
    if temp_workspace["out_dir"].exists():
        shutil.rmtree(temp_workspace["out_dir"])

    # Recreate empty directories
    temp_workspace["facts_dir"].mkdir(parents=True, exist_ok=True)
    temp_workspace["out_dir"].mkdir(parents=True, exist_ok=True)
