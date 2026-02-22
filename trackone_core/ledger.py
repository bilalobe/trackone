"""Python shim for ``trackone_core.ledger`` backed by the native extension."""

from __future__ import annotations

try:
    from ._native import ledger as _ledger
except ImportError:
    _ledger = None  # type: ignore[assignment]


def __getattr__(name: str):  # noqa: ANN201
    if _ledger is None:
        raise ImportError("Native extension not available")
    return getattr(_ledger, name)


def __dir__() -> list[str]:
    if _ledger is None:
        return []
    return sorted(set(globals()).union(dir(_ledger)))


__all__ = [n for n in dir(_ledger) if not n.startswith("_")] if _ledger else []
