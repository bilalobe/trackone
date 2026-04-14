"""Python shim for ``trackone_core.ledger`` backed by the native extension."""

from __future__ import annotations

try:
    from ._native import ledger as _ledger
except ImportError as exc:
    _ledger = None  # type: ignore[assignment]
    _native_import_error = exc
else:
    _native_import_error = None


def __getattr__(name: str):  # noqa: ANN201
    if _ledger is None:
        raise ImportError(
            "Native extension not available "
            "(trackone_core._native import failed). "
            "If running wheel tests, ensure the wheel is installed into the environment."
        ) from _native_import_error
    return getattr(_ledger, name)


def __dir__() -> list[str]:
    if _ledger is None:
        return []
    return sorted(set(globals()).union(dir(_ledger)))


__all__ = [n for n in dir(_ledger) if not n.startswith("_")] if _ledger else []
