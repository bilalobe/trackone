#!/usr/bin/env python3
"""Shared utilities for TSA and optional anchoring features."""
from __future__ import annotations

from typing import Any


def _require_requests() -> Any:
    """Import guard for optional 'requests' dependency.

    Raises:
        RuntimeError: If 'requests' is not installed with a helpful message.

    Returns:
        The requests module if available.
    """
    try:
        import requests  # local import keeps dependency optional
    except ModuleNotFoundError as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            "Anchoring features require the 'requests' package. Install it with: pip install \"trackone[anchoring]\""
        ) from exc
    return requests
