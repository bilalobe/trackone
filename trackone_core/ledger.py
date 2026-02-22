"""Python shim for ``trackone_core.ledger`` backed by the native extension."""

from __future__ import annotations

from ._native import ledger as _ledger


def __getattr__(name: str):  # noqa: ANN201
    return getattr(_ledger, name)


def __dir__() -> list[str]:
    return sorted(set(globals()).union(dir(_ledger)))


__all__ = [n for n in dir(_ledger) if not n.startswith("_")]
