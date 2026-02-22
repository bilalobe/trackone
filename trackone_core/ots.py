"""Python shim for ``trackone_core.ots`` backed by the native extension."""

from __future__ import annotations

from ._native import ots as _ots


def __getattr__(name: str):  # noqa: ANN201
    return getattr(_ots, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_ots)))


__all__ = [n for n in dir(_ots) if not n.startswith("_")]
