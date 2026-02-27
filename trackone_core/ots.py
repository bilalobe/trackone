"""Python shim for ``trackone_core.ots`` backed by the native extension."""

from __future__ import annotations

try:
    from ._native import ots as _ots
except ImportError:
    _ots = None  # type: ignore[assignment]

if _ots is not None:
    OtsStatus = _ots.OtsStatus
    OtsVerifyResult = _ots.OtsVerifyResult


def __getattr__(name: str):  # noqa: ANN201
    if _ots is None:
        raise ImportError("Native extension not available")
    return getattr(_ots, name)


def __dir__() -> list[str]:
    if _ots is None:
        return []
    return sorted(set(globals()).union(dir(_ots)))


__all__ = [n for n in dir(_ots) if not n.startswith("_")] if _ots else []
