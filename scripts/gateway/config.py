#!/usr/bin/env python3
"""
config.py

Centralized configuration for gateway environment parameters.

This module exposes environment-based knobs for OTS behavior, verification modes,
and other runtime settings. All environment variables are documented here.

Environment Variables:
- OTS_STATIONARY_STUB: When set to "1", use deterministic local OTS stubs instead
                       of calling the real `ots` binary. Default in tests.
- OTS_CALENDARS: Comma-separated list of OTS calendar URLs (forwarded to ots client).
- RUN_REAL_OTS: When set to "1", enables real OTS integration tests (slow).
- STRICT_VERIFY: When set to "1", treat verification timeouts as failures (CI main).
- STRICT_SHA: When set to "1", enforce strict SHA-256 validation.
"""

from __future__ import annotations

import os
from typing import Literal


def get_bool_env(key: str, default: bool = False) -> bool:
    """Get a boolean environment variable.

    Args:
        key: Environment variable name
        default: Default value if not set

    Returns:
        True if the env var is "1", "true", "yes" (case-insensitive),
        False if "0", "false", "no", otherwise the default.
    """
    val = os.environ.get(key, "").lower()
    if val in ("1", "true", "yes"):
        return True
    elif val in ("0", "false", "no"):
        return False
    return default


def get_str_env(key: str, default: str = "") -> str:
    """Get a string environment variable with a default."""
    return os.environ.get(key, default)


# OTS Configuration
OTS_STATIONARY_STUB: bool = get_bool_env("OTS_STATIONARY_STUB", default=False)
"""Use deterministic stationary OTS stubs instead of real ots binary."""

OTS_CALENDARS: str = get_str_env("OTS_CALENDARS", default="")
"""Comma-separated list of OTS calendar URLs."""

RUN_REAL_OTS: bool = get_bool_env("RUN_REAL_OTS", default=False)
"""Enable real OTS integration tests (slow, requires ots binary)."""

# Verification Configuration
STRICT_VERIFY: bool = get_bool_env("STRICT_VERIFY", default=False)
"""Treat verification timeouts as failures (strict mode for CI)."""

STRICT_SHA: bool = get_bool_env("STRICT_SHA", default=False)
"""Enforce strict SHA-256 validation."""


def get_ots_mode() -> Literal["stationary", "real"]:
    """Determine the current OTS operation mode.

    Returns:
        "stationary" if using deterministic stubs, "real" for actual ots client
    """
    return "stationary" if OTS_STATIONARY_STUB else "real"


def should_allow_stubs() -> bool:
    """Check if stationary OTS stubs should be accepted during verification.

    Returns:
        True if stationary stubs are allowed (test mode), False otherwise
    """
    return OTS_STATIONARY_STUB or not STRICT_VERIFY
