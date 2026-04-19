#!/usr/bin/env bash
set -euo pipefail

# This container runs the Python extension module produced by crates/trackone-gateway.
# The local k8s gateway deployment expects an HTTP server listening on :8080 with /health.
# We satisfy that by running a small FastAPI app which imports the extension module.

exec python3 /app/server.py
