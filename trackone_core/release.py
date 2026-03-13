"""Release-contract constants shared across Python and the native extension."""

from __future__ import annotations

try:
    from . import _native as _native
except ImportError:
    _native = None  # type: ignore[assignment]


DEFAULT_COMMITMENT_PROFILE_ID = getattr(
    _native,
    "DEFAULT_COMMITMENT_PROFILE_ID",
    "trackone-canonical-cbor-v1",
)

DISCLOSURE_CLASS_LABELS: dict[str, str] = {
    getattr(_native, "DISCLOSURE_CLASS_A", "A"): getattr(
        _native, "DISCLOSURE_CLASS_A_LABEL", "public-recompute"
    ),
    getattr(_native, "DISCLOSURE_CLASS_B", "B"): getattr(
        _native, "DISCLOSURE_CLASS_B_LABEL", "partner-audit"
    ),
    getattr(_native, "DISCLOSURE_CLASS_C", "C"): getattr(
        _native, "DISCLOSURE_CLASS_C_LABEL", "anchor-only-evidence"
    ),
}


__all__ = ["DEFAULT_COMMITMENT_PROFILE_ID", "DISCLOSURE_CLASS_LABELS"]
