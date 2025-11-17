"""
Integration test fixtures (module-scoped).

These fixtures are specific to integration tests that span multiple modules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# ============================================================================
# Module-scoped gateway fixtures for integration tests
# ============================================================================


@pytest.fixture(scope="module")
def frame_verifier(gateway_modules):
    """Load frame_verifier module (module-scoped for integration tests)."""
    module = gateway_modules.get("frame_verifier")
    if module is None:
        pytest.skip("frame_verifier module not available")
    return module


@pytest.fixture(scope="module")
def merkle_batcher(gateway_modules):
    """Load merkle_batcher module (module-scoped for integration tests)."""
    module = gateway_modules.get("merkle_batcher")
    if module is None:
        pytest.skip("merkle_batcher module not available")
    return module


@pytest.fixture(scope="module")
def verify_cli(gateway_modules):
    """Load verify_cli module (module-scoped for integration tests)."""
    module = gateway_modules.get("verify_cli")
    if module is None:
        pytest.skip("verify_cli module not available")
    return module


@pytest.fixture(scope="module")
def ots_anchor(gateway_modules):
    """Load ots_anchor module (module-scoped for integration tests)."""
    module = gateway_modules.get("ots_anchor")
    if module is None:
        pytest.skip("ots_anchor module not available")
    return module


@pytest.fixture(scope="module")
def crypto_utils(gateway_modules):
    """Load crypto_utils module (module-scoped for integration tests)."""
    module = gateway_modules.get("crypto_utils")
    if module is None:
        pytest.skip("crypto_utils module not available")
    return module


@pytest.fixture(scope="module")
def pod_sim(load_module):
    """Load pod_sim module (module-scoped for integration tests).

    Integration tests use the canonical implementation under `scripts/pod_sim/pod_sim.py`.
    """
    repo_root = Path(__file__).resolve().parents[2]
    pod_sim_path = repo_root / "scripts" / "pod_sim" / "pod_sim.py"
    if not pod_sim_path.exists():
        pytest.skip(f"Canonical pod_sim implementation not found at {pod_sim_path}")
    return load_module("pod_sim", pod_sim_path)


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
    import shutil

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
    import shutil

    # Reset facts_dir and out_dir before each test
    if temp_workspace["facts_dir"].exists():
        shutil.rmtree(temp_workspace["facts_dir"])
    if temp_workspace["out_dir"].exists():
        shutil.rmtree(temp_workspace["out_dir"])

    # Recreate empty directories
    temp_workspace["facts_dir"].mkdir(parents=True, exist_ok=True)
    temp_workspace["out_dir"].mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="module")
def write_device_table():
    """Return a callable that writes a device_table JSON file (module-scoped for integration tests)."""
    import json

    def _write(path, data, indent: int | None = 2):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=indent), encoding="utf-8")

    return _write


# ============================================================================
# Integration-specific helper fixtures
# ============================================================================


@pytest.fixture
def write_sample_facts_fixture():
    """Return a callable that writes sample facts to a directory (integration-specific)."""

    def _write(facts_dir: Path, facts: list[dict]):
        facts_dir.mkdir(parents=True, exist_ok=True)
        for i, fact in enumerate(facts):
            fact_file = facts_dir / f"fact_{i:03d}.json"
            fact_file.write_text(json.dumps(fact), encoding="utf-8")

    return _write


@pytest.fixture
def write_ots_placeholder():
    """Return a callable that writes an OTS placeholder (integration-specific)."""

    def _write(out_dir: Path, day: str) -> Path:
        day_bin = out_dir / "day" / f"{day}.bin"
        day_bin.parent.mkdir(parents=True, exist_ok=True)
        ots_path = day_bin.with_suffix(day_bin.suffix + ".ots")
        ots_path.write_text("OTS_PROOF_PLACEHOLDER\n", encoding="utf-8")
        return ots_path

    return _write


@pytest.fixture
def run_merkle_batcher(merkle_batcher):
    """Return a callable to run merkle_batcher (integration-specific)."""

    def _run(
        facts_dir: Path, out_dir: Path, site: str, day: str, validate: bool = True
    ) -> int:
        args = [
            "--facts",
            str(facts_dir),
            "--out",
            str(out_dir),
            "--site",
            site,
            "--date",
            day,
        ]
        if validate:
            args.append("--validate-schemas")
        return merkle_batcher.main(args)

    return _run


@pytest.fixture
def list_facts():
    """Return a callable that lists sorted fact JSON files (integration-specific)."""

    def _list(facts_dir: Path):
        if not facts_dir.exists():
            return []
        return sorted(facts_dir.glob("*.json"))

    return _list
