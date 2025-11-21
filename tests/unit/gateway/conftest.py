#!/usr/bin/env python3
"""
Gateway-scoped fixtures for unit tests under tests/unit/gateway.

Note: Gateway module loaders (frame_verifier, merkle_batcher, verify_cli, ots_anchor,
crypto_utils) are now centralized in tests/fixtures/gateway_fixtures.py and imported
via tests/conftest.py. They are available to all tests automatically.
"""
from __future__ import annotations

# All gateway module loaders are now centralized and auto-imported.
# This file can remain for any gateway-unit-test-specific fixtures if needed in the future.
