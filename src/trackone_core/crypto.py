"""Python shim for ``trackone_core.crypto`` backed by the native extension.

The native extension exposes a submodule at ``trackone_core._native.crypto``.
This shim provides the public import path ``trackone_core.crypto``.
"""

from __future__ import annotations

from typing import Any

try:
    from ._native import crypto as _crypto_impl
except ImportError:
    _crypto: Any | None = None
else:
    _crypto = _crypto_impl


def __getattr__(name: str) -> Any:
    if _crypto is None:
        raise ImportError("Native extension not available")
    return getattr(_crypto, name)


def __dir__() -> list[str]:
    if _crypto is None:
        return []
    return sorted(set(globals()).union(dir(_crypto)))


__all__ = [n for n in dir(_crypto) if not n.startswith("_")] if _crypto else []
