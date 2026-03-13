"""
Shared pytest configuration and fixtures for TrackOne tests.

This module provides:
- Module loading utilities for dynamically importing gateway and pod_sim modules
- Gateway module fixtures for accessing crypto_utils, frame_verifier, etc.
- Common test data and workspace fixtures
- Timestamp utilities for deterministic test dates
- xdist worker namespace support for parallel testing

Note on test dates:
    Tests use a fixed reference date (2025-10-07) for reproducibility.
    This ensures deterministic behavior across test runs and matches
    the checked-in demo OTS metadata sidecar. Using a fixed past date prevents
    future date-related issues.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import random
import sys
from pathlib import Path
from typing import Any

import pytest

# Ensure repo root is on sys.path so `import scripts.*` works when running tests
# directly from a checkout (pytest doesn't always add CWD under strict config).
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Import common fixtures from the fixtures package so pytest registers them.
# We prefer explicit imports and copying public symbols into this module's
# globals() so pytest always sees the fixture callables regardless of how
# pytest is invoked or what the current working directory is.
_fixture_modules = [
    "time_fixtures",  # test_date, test_timestamp, day
    "gateway_fixtures",  # frame_verifier, merkle_batcher, verify_cli, ots_anchor, crypto_utils, pod_sim
    "directory_fixtures",  # facts_dir, out_dir, temp_workspace, temp_dirs
    "sample_fixtures",  # sample_facts, sample_test_vectors, built_day_artifacts, mutate_*
    "fileio_fixtures",  # write_sample_facts_fixture, write_frame_json, append_frame_json, write_device_table, list_facts
    "ots_fixtures",  # disable_stationary_stub, enable_stationary_stub, ots_calendars
    "pipeline_fixtures",  # write_frames, write_ots_placeholder, run_merkle_batcher, run_verify_cli, run_pipeline
]

# Import fixture modules from the canonical `tests.fixtures` package only.
_fixtures_pkg = "tests.fixtures"
for _mod in _fixture_modules:
    full = f"{_fixtures_pkg}.{_mod}"
    try:
        m = importlib.import_module(full)
    except Exception:
        # Fallback: load fixture module directly from the tests/fixtures directory
        try:
            fixtures_dir = Path(__file__).resolve().parent / "fixtures"
            module_path = fixtures_dir / f"{_mod}.py"
            if module_path.exists():
                spec = importlib.util.spec_from_file_location(full, str(module_path))
                if spec is None or spec.loader is None:
                    continue
                m = importlib.util.module_from_spec(spec)
                sys.modules[full] = m
                spec.loader.exec_module(m)  # type: ignore
            else:
                # If the file doesn't exist, skip silently (some fixtures optional)
                continue
        except Exception:
            # If any error, skip this fixture module (some runs may not need all fixtures)
            continue
    for _name, _obj in vars(m).items():
        if _name.startswith("_"):
            continue
        globals().setdefault(_name, _obj)

# Reference date for all tests - ensures reproducibility
TEST_DATE = "2025-10-07"
TEST_TIMESTAMP_BASE = "2025-10-07T10:00:00Z"


# ============================================================================
# Module Loader Fixtures (Session-Scoped)
# ============================================================================


@pytest.fixture(scope="session")
def load_module():
    """Session-scoped fixture for dynamically loading Python modules from file paths.

    Returns a callable that takes (module_name, module_path) and returns the loaded module.

    Usage:
        @pytest.fixture(scope="module")
        def my_module(load_module):
            return load_module("my_module", Path("/path/to/my_module.py"))
    """

    def _load(module_name: str, module_path: Path) -> Any:
        """Load a Python module from an arbitrary file path."""
        spec = importlib.util.spec_from_file_location(module_name, str(module_path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module {module_name} from {module_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)  # type: ignore
        return module

    return _load


@pytest.fixture(scope="session")
def gateway_modules(load_module):
    """Session-scoped fixture providing lazy-loading access to gateway script modules.

    Returns a GatewayModules object with a .get(module_name) method.

    Available modules:
    - crypto_utils
    - frame_verifier
    - merkle_batcher
    - ots_anchor
    - verify_cli

    Usage:
        @pytest.fixture(scope="module")
        def crypto_utils(gateway_modules):
            module = gateway_modules.get("crypto_utils")
            if module is None:
                pytest.skip("crypto_utils module not available")
            return module
    """

    class GatewayModules:
        """Lazy-loading container for gateway modules."""

        _cache: dict[str, Any] = {}
        # Defer resolving the actual gateway directory until first use so this
        # conftest can live either under `scripts/tests` (old layout) or
        # `tests/` (new layout). We'll look for common candidate locations
        # such as `.../scripts/gateway` and `.../gateway` up the ancestor
        # chain and pick the first that exists.
        _gw_dir: Path | None = None

        @classmethod
        def get(cls, module_name: str) -> Any | None:
            """Get a gateway module by name, loading it if necessary."""
            if module_name in cls._cache:
                return cls._cache[module_name]

            # The canonical location is `scripts/gateway` at the repository root.
            # Resolve repo root by walking upwards and picking the first
            # directory that contains either `pyproject.toml`, `.git`, or a
            # `scripts/gateway` or top-level `gateway` directory. This makes
            # the fixture robust regardless of whether tests live under
            # `tests/` or `scripts/tests/`.
            if cls._gw_dir is None:
                cur = Path(__file__).resolve().parent
                repo_root = None
                for _ in range(8):
                    # heuristics for repo root candidates
                    if (cur / "pyproject.toml").exists() or (cur / ".git").exists():
                        repo_root = cur
                        break
                    if (cur / "scripts" / "gateway").exists() or (
                        cur / "gateway"
                    ).exists():
                        repo_root = cur
                        break
                    if cur.parent == cur:
                        break
                    cur = cur.parent

                if repo_root is None:
                    # last-resort: assume repository root is one level up from
                    # the tests package (this matches older layouts)
                    repo_root = Path(__file__).resolve().parents[1]

                cand = repo_root / "scripts" / "gateway"
                if cand.exists():
                    cls._gw_dir = cand
                else:
                    alt = repo_root / "gateway"
                    if alt.exists():
                        cls._gw_dir = alt
                    else:
                        # final fallback: mimic legacy behavior relative to
                        # tests directory
                        cls._gw_dir = Path(__file__).parent.parent / "gateway"

            module_path = cls._gw_dir / f"{module_name}.py"
            if not module_path.exists():
                return None

            try:
                # Ensure gateway directory is on sys.path so module-level and
                # fallback imports (e.g., 'peer_attestation') succeed when the
                # module uses relative imports or plain module imports.
                import sys

                gw_dir_str = str(cls._gw_dir)
                if gw_dir_str not in sys.path:
                    sys.path.insert(0, gw_dir_str)

                module = load_module(module_name, module_path)
                cls._cache[module_name] = module
                return module
            except Exception:
                return None

    return GatewayModules()


# ============================================================================
# xdist Worker Support (Session-Scoped)
# ============================================================================


@pytest.fixture(scope="session")
def worker_namespace() -> str:
    """Return a stable, per-worker namespace string.

    Uses PYTEST_XDIST_WORKER if available (e.g., 'gw0', 'gw1'). Defaults to 'w0'.
    This is safe without xdist; it just returns 'w0'.
    """
    return os.environ.get("PYTEST_XDIST_WORKER", "w0")


@pytest.fixture(scope="session", autouse=True)
def seed_rng(worker_namespace: str):
    """Derive a deterministic RNG seed per worker to reduce flakiness.

    - Seeds Python's random module
    - Sets PYTHONHASHSEED for deterministic hashing in this process
    - Provides TEST_TIME_OFFSET for optional filename jitter if needed
    """
    seed = int(hashlib.sha256(worker_namespace.encode()).hexdigest(), 16) % (2**32)
    random.seed(seed)  # rng-ok: deterministic seeding for reproducible tests
    os.environ.setdefault("PYTHONHASHSEED", str(seed))
    os.environ.setdefault("TEST_TIME_OFFSET", str(seed % 13))
    os.environ.setdefault("OTS_STATIONARY_STUB", "1")


@pytest.fixture(scope="session")
def session_base_dir(tmp_path_factory, worker_namespace: str) -> Path:
    """Base temporary directory unique per worker for session-scoped outputs."""
    return tmp_path_factory.mktemp(f"session-{worker_namespace}")


@pytest.fixture(scope="session")
def session_out_dir(session_base_dir: Path) -> Path:
    """Session-scoped output directory for batch processing."""
    d = session_base_dir / "out"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture(scope="session")
def session_frames_dir(session_base_dir: Path) -> Path:
    """Session-scoped frames directory."""
    d = session_base_dir / "frames"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture(scope="session")
def session_facts_dir(session_base_dir: Path) -> Path:
    """Session-scoped facts directory."""
    d = session_base_dir / "facts"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ============================================================================
# Helper Functions (Module-Level)
# ============================================================================


# The helper fixtures such as `write_sample_facts_fixture`, `sample_facts`,
# `temp_workspace`, etc. are defined in `scripts/tests/fixtures/common_fixtures.py`.
# Use `load_facts_dir` here as a small helper for tests that need to read a
# facts directory (kept in conftest for convenience).


def load_facts_dir(facts_dir: Path) -> list[dict[str, Any]]:
    """Load all fact JSON files from a directory in sorted order."""
    if not facts_dir.exists():
        return []
    return [
        json.loads(f.read_text(encoding="utf-8"))
        for f in sorted(facts_dir.glob("*.json"))
    ]


# ============================================================================
# Pytest Hooks and Configuration
# ============================================================================


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow (deselect with '-m \"not slow\"')",
    )
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests",
    )
    config.addinivalue_line(
        "markers",
        "e2e: marks tests as end-to-end tests",
    )
    config.addinivalue_line(
        "markers",
        "unit: marks tests as unit tests",
    )
    config.addinivalue_line(
        "markers",
        "crypto: marks tests that exercise cryptographic operations",
    )
    config.addinivalue_line(
        "markers",
        "real_ots: marks tests that require real OTS binary (slow and optional)",
    )


def pytest_itemcollected(item):
    """Early auto-marking during collection for xdist compatibility.

    This ensures '-m <marker>' selection works even with xdist's loadscope
    scheduler by applying marks as soon as items are collected.
    """
    lid = item.nodeid.lower()
    name = item.name.lower()

    if "ots" in lid or "pipeline" in lid:
        item.add_marker(pytest.mark.slow)
    if "end_to_end" in name or "e2e" in lid or "framed" in name:
        item.add_marker(pytest.mark.e2e)
    if "integration" in lid:
        item.add_marker(pytest.mark.integration)
    if "unit" in lid:
        item.add_marker(pytest.mark.unit)
    if "crypto" in lid or "test_crypto" in lid:
        item.add_marker(pytest.mark.crypto)


# ---------------------------------------------------------------------------
# Convenience autouse fixture: expose gateway module symbols into test modules
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _expose_gateway_symbols(request, gateway_modules):
    """Expose common gateway functions / modules into each test module's globals.

    Many test modules define module-level helper functions that reference names
    like `canonical_json`, `merkle_root_from_leaves`, `frame_verifier`, etc.
    Those helpers run at test time (not import time) and expect the fixture
    values to be available as plain globals. To avoid editing many tests, we
    populate the test module's globals with values loaded from the gateway
    scripts if they aren't already present.

    This is intentionally conservative: we only set a name if it doesn't
    already exist in the module, and we skip silently when the gateway module
    or attribute isn't available (tests will skip earlier where appropriate).
    """
    mod = getattr(request, "module", None)
    if mod is None:
        return

    # Mapping: target_name -> (gateway_module_name, attribute_name_or_None)
    mapping = {
        # merkle_batcher exports
        "canonical_json": ("merkle_batcher", "canonical_json"),
        "merkle_root_from_leaves": ("merkle_batcher", "merkle_root_from_leaves"),
        "BlockHeader": ("merkle_batcher", "BlockHeader"),
        "load_schemas": ("merkle_batcher", "load_schemas"),
        "validate_against_schema": ("merkle_batcher", "validate_against_schema"),
        "batcher_main": ("merkle_batcher", "main"),
        # verify_cli exports
        "verify_merkle_root": ("verify_cli", "merkle_root"),
        "verify_cli": ("verify_cli", None),
        # frame verifier and other gateway modules
        "frame_verifier": ("frame_verifier", None),
        "crypto_utils": ("crypto_utils", None),
        "ots_anchor": ("ots_anchor", None),
        "merkle_batcher": ("merkle_batcher", None),
        # pod_sim helpers used by several tests
        "pod_sim": ("pod_sim", None),
    }

    for tgt_name, (gw_mod_name, gw_attr) in mapping.items():
        # Prefer resolving an existing fixture to its concrete value so
        # tests referencing the name at module scope see the module object
        # instead of the fixture function. Use request.getfixturevalue which
        # will resolve the fixture if present.
        if hasattr(mod, tgt_name):
            existing = getattr(mod, tgt_name)
            if callable(existing):
                with contextlib.suppress(Exception):
                    val = request.getfixturevalue(tgt_name)
                    # Replace the module-level name with the resolved fixture
                    setattr(mod, tgt_name, val)
                    continue

                # If fixture resolution fails, fall back to attaching
                # attributes from gateway module (if available) to the
                # existing callable to preserve some behavior.

                gw = None
                with contextlib.suppress(Exception):
                    gw = gateway_modules.get(gw_mod_name)

                if gw is None:
                    continue

                for attr in dir(gw):
                    # include private names as tests may access underscored helpers
                    if hasattr(existing, attr):
                        continue
                    with contextlib.suppress(Exception):
                        setattr(existing, attr, getattr(gw, attr))
                continue

        # If no existing callable fixture, try to set module-level name from
        # gateway_modules (lazy load). This covers cases where tests expect a
        # top-level module symbol but don't define a fixture.
        gw = None
        with contextlib.suppress(Exception):
            gw = gateway_modules.get(gw_mod_name)
        if gw is None:
            continue
        value = gw if gw_attr is None else getattr(gw, gw_attr, None)
        if value is not None:
            with contextlib.suppress(Exception):
                setattr(mod, tgt_name, value)
