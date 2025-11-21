"""
Shared pytest fixtures for TrackOne tests.

This module aggregates fixtures from specialized fixture modules for convenience.
All fixtures are available after importing this module or any of its sub-modules.

Fixture categories:
- time_fixtures: test_date, test_timestamp, day
- gateway_fixtures: frame_verifier, merkle_batcher, verify_cli, crypto_utils, ots_anchor
- pod_sim_fixtures: pod_sim, test_vectors
- directory_fixtures: facts_dir, out_dir, temp_workspace (deprecated—use module-scoped in tests/integration/conftest.py), temp_dirs
- sample_fixtures: sample_facts, sample_test_vectors, crypto_test_vectors_path
- fileio_fixtures: write_sample_facts_fixture, write_frame_json, append_frame_json, write_device_table, list_facts
- ots_fixtures: disable_stationary_stub, enable_stationary_stub, ots_calendars
- pipeline_fixtures: write_frames, write_ots_placeholder, run_merkle_batcher, run_verify_cli, run_pipeline
"""

from __future__ import annotations

from .directory_fixtures import *  # noqa: F401,F403 # rng-ok
from .ots_fixtures import *  # noqa: F401,F403 # rng-ok

# noqa: F401 # rng-ok
from .time_fixtures import day, test_date, test_timestamp  # noqa: F401 # rng-ok
