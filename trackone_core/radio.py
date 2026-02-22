"""Python shim for ``trackone_core.radio`` that forwards to the root ``_native`` module (PyRadio is a top-level class, not a submodule)."""

from __future__ import annotations

from . import _native as _radio


def __getattr__(name: str):  # noqa: ANN201
    return getattr(_radio, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_radio)))


# Explicitly define the public API of trackone_core.radio.
# Only PyRadio is exported via `from trackone_core.radio import *`.
__all__ = ["PyRadio"]
