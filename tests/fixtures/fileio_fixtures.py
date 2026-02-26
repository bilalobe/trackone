#!/usr/bin/env python3
"""
File I/O and data manipulation fixtures.

Provides fixtures for writing facts, frames, device tables, and listing files.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    from scripts.gateway.canonical_cbor import canonicalize_obj_to_cbor
except ImportError:  # pragma: no cover - fallback for direct test module execution
    from canonical_cbor import canonicalize_obj_to_cbor  # type: ignore


@pytest.fixture
def write_sample_facts_fixture():
    """Write sample facts to a directory.

    Returns a callable that takes (facts_dir, facts_list) and writes each fact
    as an authoritative CBOR file with a JSON projection.
    """

    def _write(facts_dir: Path, facts: list[dict]):
        facts_dir = Path(facts_dir)
        facts_dir.mkdir(parents=True, exist_ok=True)
        for i, fact in enumerate(facts):
            fact_stem = facts_dir / f"fact_{i:03d}"
            fact_stem.with_suffix(".cbor").write_bytes(canonicalize_obj_to_cbor(fact))
            fact_stem.with_suffix(".json").write_text(
                json.dumps(fact), encoding="utf-8"
            )

    return _write


@pytest.fixture
def write_frame_json():
    """Write a JSON object as a single line to a frames file.

    Returns a callable that takes (frames_path, obj) and writes the object
    as NDJSON (newline-delimited JSON).
    """

    def _write(frames_path: Path, obj: dict):
        frames_path = Path(frames_path)
        frames_path.parent.mkdir(parents=True, exist_ok=True)
        frames_path.write_text(json.dumps(obj) + "\n", encoding="utf-8")

    return _write


@pytest.fixture
def append_frame_json():
    """Append a JSON object as a single line to a frames file.

    Returns a callable that takes (frames_path, obj) and appends the object
    as NDJSON.
    """

    def _append(frames_path: Path, obj: dict):
        frames_path = Path(frames_path)
        frames_path.parent.mkdir(parents=True, exist_ok=True)
        with frames_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj) + "\n")

    return _append


@pytest.fixture(scope="module")
def write_device_table():
    """Write a device_table JSON file (module-scoped).

    Returns a callable that takes (path, data, indent=2) and writes the device
    table as formatted JSON.
    """

    def _write(path, data, indent: int | None = 2):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=indent), encoding="utf-8")

    return _write


@pytest.fixture
def list_facts():
    """List sorted authoritative fact CBOR files from a directory.

    Returns a callable that takes (facts_dir) and returns a sorted list of
    .cbor file paths.
    """

    def _list(facts_dir: Path):
        facts_dir = Path(facts_dir)
        if not facts_dir.exists():
            return []
        return sorted(facts_dir.glob("*.cbor"))

    return _list
