"""Python shim for ``trackone_core.radio`` backed by the native extension.

`PyRadio` is exposed as a top-level class in the native module, not as a nested
submodule, so this shim forwards attribute access to `trackone_core._native`.
"""

from __future__ import annotations

try:
    from . import _native as _radio
except ImportError:
    _radio = None  # type: ignore[assignment]


def __getattr__(name: str):  # noqa: ANN201
    if _radio is None:
        raise ImportError("Native extension not available")
    return getattr(_radio, name)


def __dir__() -> list[str]:
    if _radio is None:
        return []
    return sorted(set(globals()).union(dir(_radio)))


__all__ = ["PyRadio"] if _radio is not None and hasattr(_radio, "PyRadio") else []
