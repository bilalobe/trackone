"""Python package wrapper for the optional native TrackOne extension.

This repo ships a PyO3 extension for performance-critical Merkle/ledger logic.
The native module is built as `trackone_core._native`, and this package provides
a stable import surface:

    import trackone_core
    trackone_core.merkle.merkle_root_hex(...)
"""

from __future__ import annotations

# Importing the extension is optional for some workflows; callers that want it
# should handle ImportError. The native extension may not be available if the
# package was installed without building the Rust extension.
from . import crypto as crypto  # noqa: F401
from . import ledger as ledger  # noqa: F401
from . import merkle as merkle  # noqa: F401
from . import ots as ots  # noqa: F401
from . import release as release  # noqa: F401

try:
    from . import radio as radio  # noqa: F401
except Exception:
    # Radio is optional; a failure to import it must not prevent importing the
    # rest of the package.
    radio = None  # type: ignore[assignment]

try:
    from . import _native as _native  # noqa: F401
except ImportError:
    _native = None  # type: ignore[assignment]

__version__ = getattr(_native, "__version__", "0.0.0") if _native else "0.0.0"


def __getattr__(name: str):  # noqa: ANN201
    # Keep `import trackone_core` working without the native extension, but fail
    # loudly if callers try to use the native surface.
    if name in {"Gateway", "GatewayBatch", "PyRadio"}:
        if _native is None:
            raise ImportError("Native extension not available")
        return getattr(_native, name)
    raise AttributeError(name)


__all__ = [
    "__version__",
    "crypto",
    "ledger",
    "merkle",
    "ots",
    "release",
]
