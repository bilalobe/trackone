"""Python shim for ``trackone_core.merkle`` backed by the native extension."""

from __future__ import annotations

try:
    from ._native import merkle as _merkle
except ImportError:
    _merkle = None  # type: ignore[assignment]


def __getattr__(name: str):  # noqa: ANN201
    if _merkle is None:
        raise ImportError("Native extension not available")
    return getattr(_merkle, name)


def __dir__() -> list[str]:
    if _merkle is None:
        return []
    return sorted(set(globals()).union(dir(_merkle)))


__all__ = [n for n in dir(_merkle) if not n.startswith("_")] if _merkle else []
