"""Python package wrapper for the optional native TrackOne extension.

This repo ships a PyO3 extension for performance-critical Merkle/ledger logic.
The native module is built as `trackone_core._native`, and this package provides
a stable import surface:

    import trackone_core
    trackone_core.merkle.merkle_root_hex(...)
"""

from __future__ import annotations

# Importing the extension is optional for some workflows; callers that want it
# should handle ImportError. We intentionally do not swallow ImportError here to
# avoid masking build/ABI problems.
from . import _native as _native  # noqa: F401
from . import crypto as crypto  # noqa: F401
from . import ledger as ledger  # noqa: F401
from . import merkle as merkle  # noqa: F401
from . import ots as ots  # noqa: F401
from . import radio as radio  # noqa: F401

Gateway = _native.Gateway
GatewayBatch = _native.GatewayBatch
PyRadio = _native.PyRadio

__version__ = getattr(_native, "__version__", "0.0.0")

__all__ = [
    "Gateway",
    "GatewayBatch",
    "PyRadio",
    "__version__",
    "crypto",
    "ledger",
    "merkle",
    "ots",
    "radio",
]
