"""Python shim for ``trackone_core.radio`` backed by the native extension."""

from __future__ import annotations

from ._native import radio as _radio


def __getattr__(name: str):  # noqa: ANN201
    return getattr(_radio, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_radio)))


__all__ = [n for n in dir(_radio) if not n.startswith("_")]
