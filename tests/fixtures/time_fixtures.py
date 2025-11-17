"""
Time and timestamp fixtures for tests.

Common time-related utilities used across multiple test suites.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

# Reference date constants
TEST_DATE = "2025-10-07"
TEST_TIMESTAMP_BASE = "2025-10-07T10:00:00Z"


@pytest.fixture(scope="module")
def test_date() -> str:
    """Return the canonical test date string (module-scoped)."""
    return TEST_DATE


@pytest.fixture(scope="module")
def test_timestamp():
    """Return a callable that generates ISO 8601 timestamps with optional offsets (module-scoped).

    Usage:
        timestamp = test_timestamp(300) # 300 seconds after base time
    """

    def _gen(offset_seconds: int = 0) -> str:
        base = datetime.fromisoformat(TEST_TIMESTAMP_BASE.replace("Z", "+00:00"))
        new_time = base + timedelta(seconds=offset_seconds)
        return new_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    return _gen


@pytest.fixture(scope="module")
def day() -> str:
    """Return the canonical test day string used across tests (module-scoped)."""
    return TEST_DATE
