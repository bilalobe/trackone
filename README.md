# TrackOne — Ultra‑Low‑Power, Verifiable Telemetry

[![CI](https://github.com/bilalobe/trackone/actions/workflows/ci.yml/badge.svg)](https://github.com/bilalobe/trackone/actions/workflows/ci.yml) [![OTS Verify](https://github.com/bilalobe/trackone/actions/workflows/ots-verify.yml/badge.svg)](https://github.com/bilalobe/trackone/actions/workflows/ots-verify.yml) [![codecov](https://codecov.io/gh/bilalobe/trackone/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/trackone) [![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

TrackOne is a reference pipeline for secure, energy‑efficient telemetry collection with end‑to‑end verifiability.
It focuses on:

- Compact frame format suitable for ultra‑low‑power devices
- Modern cryptography (X25519, XChaCha20‑Poly1305, Ed25519)
- Canonicalization and Merkle batching for tamper‑evident storage
- Public timestamping via OpenTimestamps (OTS)

The goal is to let anyone independently verify what the gateway claims without trusting its operator or database.

## Status

- Language: Python 3.11+
- Packaging: Hatchling (`pyproject.toml`)
- License: MIT
- ADRs: See `adr/` for design decisions and milestone status

> This repository includes both a runnable demo pipeline and a collection of scripts and tools. See Quickstart below.

## Table of Contents

- Overview
- Architecture at a Glance
- Quickstart (Demo)
- Installation (dev/prod)
- Usage
  - Verify a day’s batch and OTS proof
  - Make targets
- Repository Layout
- Security & Trust Model
- Development
- Benchmarks
- ADRs (Architecture Decision Records)
- Roadmap
- Contributing
- License

## Overview

TrackOne implements a forward‑only, auditable telemetry pipeline. Devices produce framed, authenticated messages that a gateway ingests, deduplicates (replay window), canonicalizes, batches into a Merkle tree, and anchors daily digests via OTS. Auditors can re‑compute Merkle roots from canonical facts and verify OTS proofs to ensure integrity and existence at time.

Key properties:

- Deterministic, canonical JSON for all facts
- Hash‑sorted Merkle leaves for order independence
- Daily chaining via previous day root
- OTS anchor for public, trust‑minimized timestamping

See ADR‑001/002/003 in `adr/` for the rationale and details.

## Architecture at a Glance

- Framing and Crypto (ADR‑001, ADR‑002)
  - X25519 + HKDF for key derivation
  - XChaCha20‑Poly1305 for AEAD
  - Ed25519 for firmware/config signatures
  - Nonce construction and replay window policy
- Canonicalization & Merkle (ADR‑003)
  - Canonical JSON (sorted keys, UTF‑8, no whitespace)
  - Hash‑sorted leaves → Merkle root
  - Day chaining and block header with authoritative root
- Timestamping
  - OpenTimestamps proof for the day blob (`day.bin.ots`)

## Quickstart (Demo)

Requirements:

- Python 3.11+
- macOS/Linux shell (tested on Linux)
- Optional: `ots` CLI in PATH for real OTS verification

1. Set up a virtualenv and install dev deps:

```
python -m venv .venv
source .venv/bin/activate
make dev-setup
```

2. Run the end‑to‑end pipeline:

```
make run
```

This will execute the demo flow under `out/site_demo/`:

- Ingest simulated frames
- Verify/de‑dupe and emit canonical facts
- Batch facts into a Merkle root and write a block header
- Create or stub an OTS proof for the day blob
- Verify the root and OTS proof via the CLI

Artifacts are written under:

- `out/site_demo/facts/` – canonical fact JSON
- `out/site_demo/blocks/` – block header (day, merkle_root, prev_day_root)
- `out/site_demo/day/` – `YYYY-MM-DD.bin` and `YYYY-MM-DD.bin.ots`

## Installation

Production dependencies only:

```
make install
```

Development environment (linters, tests, etc.):

```
make dev-setup
```

Alternatively, use `requirements.txt` and `requirements-dev.txt` directly with `pip`.

## Usage

### Verify a day’s batch and OTS proof

You can independently verify a batch using the provided CLI. By default it expects example facts; pass your own `--facts` to verify a real directory of canonical JSON facts.

```
python scripts/gateway/verify_cli.py --root out/site_demo --facts toolset/unified/examples
```

Exit codes:

- `0` OK: root matches and OTS verified
- `1` Block header invalid/missing day
- `2` Merkle root mismatch
- `3` OTS file missing
- `4` OTS verification failed

Notes:

- If `ots` is not installed, tests and the demo may use a placeholder OTS proof to keep the flow runnable.
- For real OTS verification, install the `ots` binary and re‑run.

### Common Make targets

```
make help          # Show all documented targets
make run           # Run demo pipeline end‑to‑end
make test          # Run test suite
make test-cov      # Run tests with coverage (HTML in htmlcov/)
make lint          # Ruff + Black checks (if installed)
make format        # Format code with Black
make sec-scan      # Bandit + pip-audit
make bench         # Run pytest-benchmark suite
make ots-verify    # Verify OTS proofs in out/site_demo/day
```

Advanced testing:

```
make test-parallel  # Use pytest-xdist
make test-fast      # Exclude slow tests
make test-crypto    # Only crypto tests
make test-slowest   # Show slowest tests
```

## Quick validate

Run the full demo (pipeline → sha → ots) in one shot:

```bash
make e2e
```

Strict modes and options:

```bash
# Require JSON-declared sha256 and matching value
STRICT_SHA=1 make e2e

# Run OTS with a local bitcoind (headers-only) and fail if verification fails
RUN_BITCOIND=1 STRICT_VERIFY=1 make e2e

# Only run the pipeline
make pipeline-quick

# Only verify SHA
make sha-verify

# Only verify OTS (strict)
make ots-verify-strict
```

One-shot test run:

```bash
# Replace TEST with a node id or file::test
make test-one TEST="tests/unit/crypto/test_hkdf.py::TestHKDF::test_deterministic_derivation -q"
```

Real OTS integration tests (optional):

```bash
# Enable real OTS tests (skipped by default)
RUN_REAL_OTS=1 tox -e py313 -- -m real_ots -q tests/integration/test_ots_integration.py

# When a stationary calendar is available, prefer it by exporting calendars:
export OTS_CALENDARS="https://calendar.local:8468 https://a.pool.opentimestamps.org"
# or comma-separated
export OTS_CALENDARS="https://calendar.local:8468,https://a.pool.opentimestamps.org"
```

Stationary OTS calendar (future): see ADR-014 for the plan to run an internal calendar
service to improve determinism and reduce reliance on public pools.

## Repository Layout

- `scripts/`
  - `gateway/` – verifier, Merkle batcher, OTS anchoring, CLI tools
  - `pod_sim/` – simulator for device frames and vectors
  - `ci/` – CI helpers (e.g., OTS verification script)
- `toolset/` – examples, test vectors, and utilities
- `adr/` – Architecture Decision Records and index
- `tests/` – unit/integration tests and markers
- `out/` – demo run artifacts (ignored by VCS)
- `docs/` – project docs (if any)
- `pyproject.toml` – build/packaging config
- `Makefile` – developer and CI workflows

## Security & Trust Model

- Canonicalization + Merkle policy and daily anchoring are defined in ADR‑003.
- The gateway outputs:
  - Canonical fact files (auditable inputs)
  - Block header with authoritative Merkle root
  - Daily blob and OTS proof
- Auditors recompute the Merkle root from facts and verify OTS on the day blob to get a public, trust‑minimized timestamp.
- Crypto primitives and framing policies are specified in ADR‑001/002. See code comments for references to specific ADRs.

## Development

- Code style: Black + Ruff. Use `make lint` and `make format`.
- Tests: `pytest` with markers and xdist. See `pyproject.toml` for config.
- Coverage: `make test-cov` produces `htmlcov/index.html`.
- Security: `make sec-scan` runs Bandit and pip‑audit.
- Git hooks: See `.pre-commit-config.yaml` if you use pre‑commit.

Create a branch, open a PR, and reference ADR IDs in docstrings/comments when relevant (e.g., “implements ADR‑002 nonce policy”).

## Benchmarks

Micro/mid‑level benchmarks (see ADR‑011) can be run via:

```
make bench
```

Outputs are saved under `out/benchmarks/`.

## ADRs (Architecture Decision Records)

The design is documented via ADRs in `adr/`. Start with the index:

- `adr/README.md` – overview and status
- Examples:
  - ADR‑001: Cryptographic Primitives and Framing
  - ADR‑002: Telemetry Framing, Nonce/Replay Policy
  - ADR‑003: Canonicalization, Merkle Policy, Daily OTS Anchoring
  - ADR‑012: Parquet Export for Telemetry Facts (proposed)

When changing behavior that contradicts an Accepted ADR, propose a new ADR first.

## Roadmap

- M#2+: Real AEAD in gateway path (XChaCha20‑Poly1305) everywhere
- Persistent state and improved replay window policies
- Parquet exporter for analytics (ADR‑012)
- CI: headers‑only Bitcoin Core caching for trustless OTS verification

See `CHANGELOG.md` for released changes.

## Contributing

Please see `CONTRIBUTING.md` for guidelines. High‑level process:

- Discuss large changes with an ADR proposal
- Keep code aligned with accepted ADRs
- Add/adjust tests alongside changes

## License

MIT © 2025 TrackOne contributors
