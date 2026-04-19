"""Python shim for ``trackone_core.merkle`` backed by the native extension."""

from __future__ import annotations

from typing import Any

try:
    from ._native import merkle as _merkle_impl
except ImportError:
    _merkle: Any | None = None
else:
    _merkle = _merkle_impl


def __getattr__(name: str) -> Any:
    if _merkle is None:
        raise ImportError("Native extension not available")
    return getattr(_merkle, name)


def __dir__() -> list[str]:
    if _merkle is None:
        return []
    return sorted(set(globals()).union(dir(_merkle)))


__all__ = [n for n in dir(_merkle) if not n.startswith("_")] if _merkle else []
