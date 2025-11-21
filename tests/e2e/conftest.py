"""
End-to-end test fixtures (module-scoped).

These fixtures are specific to e2e tests that run the full pipeline.

Note: All fixtures (gateway loaders, file I/O helpers, pipeline runners) are now
centralized in tests/fixtures/ and auto-imported via tests/conftest.py.
This file can remain for any e2e-specific overrides if needed in the future.
"""
from __future__ import annotations

# All fixtures are now centralized in tests/fixtures/ and automatically
# imported by tests/conftest.py. No e2e-specific fixtures are needed.
