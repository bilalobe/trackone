"""Python shim for ``trackone_core.sensorthings`` backed by the native extension."""

from __future__ import annotations

try:
    from ._native import sensorthings as _sensorthings
except ImportError:
    _sensorthings = None  # type: ignore[assignment]


def __getattr__(name: str):  # noqa: ANN201
    if _sensorthings is None:
        raise ImportError("Native extension not available")
    return getattr(_sensorthings, name)


def __dir__() -> list[str]:
    if _sensorthings is None:
        return []
    return sorted(set(globals()).union(dir(_sensorthings)))


__all__ = (
    [n for n in dir(_sensorthings) if not n.startswith("_")] if _sensorthings else []
)
