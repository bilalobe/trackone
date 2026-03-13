"""Release-contract constants shared across Python and the native extension."""

from __future__ import annotations

try:
    from . import _native as _native
except ImportError:
    _native = None  # type: ignore[assignment]


def _native_str(name: str, default: str) -> str:
    value = getattr(_native, name, default)
    return value if isinstance(value, str) else default


DEFAULT_COMMITMENT_PROFILE_ID = _native_str(
    "DEFAULT_COMMITMENT_PROFILE_ID",
    "trackone-canonical-cbor-v1",
)

DISCLOSURE_CLASS_LABELS: dict[str, str] = {
    _native_str("DISCLOSURE_CLASS_A", "A"): _native_str(
        "DISCLOSURE_CLASS_A_LABEL",
        "public-recompute",
    ),
    _native_str("DISCLOSURE_CLASS_B", "B"): _native_str(
        "DISCLOSURE_CLASS_B_LABEL",
        "partner-audit",
    ),
    _native_str("DISCLOSURE_CLASS_C", "C"): _native_str(
        "DISCLOSURE_CLASS_C_LABEL",
        "anchor-only-evidence",
    ),
}


__all__ = ["DEFAULT_COMMITMENT_PROFILE_ID", "DISCLOSURE_CLASS_LABELS"]
