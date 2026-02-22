"""Python shim for ``trackone_core.merkle`` backed by the native extension."""

from __future__ import annotations

from ._native import merkle as _merkle


def __getattr__(name: str):  # noqa: ANN201
    return getattr(_merkle, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_merkle)))


__all__ = [n for n in dir(_merkle) if not n.startswith("_")]
