"""Rust-backed constants exposed through the Python package."""

from __future__ import annotations

try:
    from . import _native as _native
except ImportError:
    _native = None


def _native_str(name: str, default: str) -> str:
    value = getattr(_native, name, default)
    return value if isinstance(value, str) else default


def _native_int(name: str, default: int) -> int:
    value = getattr(_native, name, default)
    return value if isinstance(value, int) and not isinstance(value, bool) else default


INGEST_PROFILE_RUST_POSTCARD_V1 = _native_str(
    "INGEST_PROFILE_RUST_POSTCARD_V1",
    "rust-postcard-v1",
)
DEFAULT_INGEST_PROFILE = INGEST_PROFILE_RUST_POSTCARD_V1
INGEST_PROFILES = (DEFAULT_INGEST_PROFILE,)
FRAMED_FACT_MSG_TYPE = _native_int("FRAMED_FACT_MSG_TYPE", 1)

OTS_VERIFY_TIMEOUT_SECS = _native_int("OTS_VERIFY_TIMEOUT_SECS", 30)


__all__ = [
    "INGEST_PROFILE_RUST_POSTCARD_V1",
    "DEFAULT_INGEST_PROFILE",
    "INGEST_PROFILES",
    "FRAMED_FACT_MSG_TYPE",
    "OTS_VERIFY_TIMEOUT_SECS",
]
