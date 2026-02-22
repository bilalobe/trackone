"""Python shim for ``trackone_core.crypto`` backed by the native extension.

The native extension exposes a submodule at ``trackone_core._native.crypto``.
This shim provides the public import path ``trackone_core.crypto``.
"""

from __future__ import annotations

try:
    from ._native import crypto as _crypto
except ImportError:
    _crypto = None  # type: ignore[assignment]


def __getattr__(name: str):  # noqa: ANN201
    if _crypto is None:
        raise ImportError("Native extension not available")
    return getattr(_crypto, name)


def __dir__() -> list[str]:
    if _crypto is None:
        return []
    return sorted(set(globals()).union(dir(_crypto)))


__all__ = [n for n in dir(_crypto) if not n.startswith("_")] if _crypto else []
