# tests/bench/test_perf.py
import hashlib
import os
import pathlib

import pytest

# Skip cleanly if pytest-benchmark is not installed
pytest.importorskip("pytest_benchmark")

# Resolve project root relative to this file
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]
ENV_OTS_FILE = os.getenv("OTS_BIN_FILE")

FILE_CANDIDATES = []
if ENV_OTS_FILE:
    FILE_CANDIDATES.append(pathlib.Path(ENV_OTS_FILE))
FILE_CANDIDATES += [
    PROJECT_ROOT / "out/site_demo/day/2025-10-07.cbor.ots",
    PROJECT_ROOT / "out/site_demo/day/2025-10-07.cbor",
]


@pytest.fixture(scope="session")
def ots_file():
    for p in FILE_CANDIDATES:
        if p.exists() and p.is_file():
            return p
    pytest.skip("No real OTS .cbor file found in expected locations")
    return None


def _read_bin(path: pathlib.Path) -> bytes:
    return path.read_bytes()


def _hash_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def test_read_ots_bin(benchmark, ots_file):
    data = benchmark(_read_bin, ots_file)
    assert len(data) > 0


def test_hash_ots_bin(benchmark, ots_file):
    data = _read_bin(ots_file)
    digest = benchmark(_hash_bytes, data)
    assert len(digest) == 32
