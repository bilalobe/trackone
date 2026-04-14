"""Python shim for ``trackone_core.ots`` backed by the native extension."""

from __future__ import annotations

from typing import Any

try:
    from ._native import ots as _ots_impl
except ImportError:
    _ots: Any | None = None
else:
    _ots = _ots_impl

if _ots is not None:
    if hasattr(_ots, "OtsStatus"):
        OtsStatus = _ots.OtsStatus
    if hasattr(_ots, "OtsVerifyResult"):
        OtsVerifyResult = _ots.OtsVerifyResult


def __getattr__(name: str) -> Any:
    if _ots is None:
        raise ImportError("Native extension not available")
    return getattr(_ots, name)


def __dir__() -> list[str]:
    if _ots is None:
        return []
    return sorted(set(globals()).union(dir(_ots)))


__all__ = [n for n in dir(_ots) if not n.startswith("_")] if _ots else []
