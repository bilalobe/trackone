# Track1 — Ultra–Low‑Power, Verifiable Telemetry (Barnacle Sentinel)

[![CI](https://github.com/bilalobe/trackone/actions/workflows/ci.yml/badge.svg)](https://github.com/bilalobe/trackone/actions/workflows/ci.yml)
[![OTS Verify](https://github.com/bilalobe/trackone/actions/workflows/ots-verify.yml/badge.svg)](https://github.com/bilalobe/trackone/actions/workflows/ots-verify.yml)
[![codecov](https://codecov.io/gh/bilalobe/trackone/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/trackone)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

This repository contains the code and documents for Track1: secure pod→gateway telemetry with daily, publicly verifiable
timestamp proofs (OpenTimestamps), plus deterministic batching and schemas.

**Current Status**: M#4 — OTS proof verification finalized, Bitcoin block 919384 anchoring confirmed
**Release Date**: October 21, 2025
**Test Coverage**: 73 tests passing, 85% code coverage
**CI/CD**: Python 3.11/3.12/3.13 with uv package manager; OTS verification policy per ADR-007

## ✨ What's New in M#4

- ✅ **OTS proof verification finalized**: Production day blob anchored to Bitcoin block 919384
- ✅ **Proof metadata**: `proofs/2025-10-07.ots.meta.json` captures block height, hash, merkleroot, and artifact SHA256
- ✅ **Git LFS tracking**: `.ots` files tracked via Git LFS to prevent repo bloat
- ✅ **End-to-end verification**: Local Bitcoin Core validation (headers-only/pruned-safe)
- ✅ **ADR-008**: Milestone M#4 completion and OTS verification workflow documentation
- ✅ **Test suite fix**: Enhanced `verify_cli.py` to handle test placeholders (73/73 tests passing)

### OTS Verification Details (M#4)

```bash
# Verify OTS proof locally (requires Bitcoin Core node)
ots verify out/site_demo/day/2025-10-07.bin.ots
# Success! Bitcoin block 919384 attests existence as of 2025-10-16 IST

# Confirm merkle root matches Bitcoin block header
bitcoin-cli getblockheader $(bitcoin-cli getblockhash 919384) | jq -r .merkleroot
# 166c8fe05f6071d8a29145c4e52c039159c699f3278c45d1c3107503b59c8047

# Run project's end-to-end verifier
python scripts/gateway/verify_cli.py --root out/site_demo --facts out/site_demo/facts
# OK: root matches and OTS verified
```

**Proof metadata**: See `proofs/2025-10-07.ots.meta.json` for complete verification details.

## ✨ What's New in M#3

- ✅ **Real XChaCha20-Poly1305 AEAD** with tag verification (no more stubs!)
- ✅ **PyNaCl migration** (ADR-005): Single cryptographic library for all primitives
- ✅ **Device table schema v1.0** (ADR-006): Forward-only policy, no migrations
- ✅ **Comprehensive testing**: 73 tests including property-based (Hypothesis) and security tests
- ✅ **Deterministic AEAD vectors**: Reproducible cryptographic test vectors
- ✅ **Enhanced CI/CD**: uv-based workflow, Python 3.11-3.13 matrix, lint + test jobs
- ✅ **85% code coverage** with detailed reports

## Quick start (M#3)

Run the complete end-to-end pipeline with real AEAD encryption:

```bash
make run
```

This demonstrates the full M#3 workflow with production cryptography:

1. **pod_sim --framed** → generates encrypted framed telemetry with XChaCha20-Poly1305
1. **frame_verifier.py** → decrypts frames, verifies authentication tags, enforces replay window

## Manual step-by-step (M#3)

4. **ots_anchor.py** → timestamps day blob via OpenTimestamps
   Run each pipeline step individually to understand the workflow:

Outputs land in `out/site_demo/`:

# 1) Generate encrypted framed telemetry (10 frames from pod-003)

- `frames.ndjson` — encrypted framed telemetry records
- `facts/*.json` — canonical fact files (decrypted payloads)
- `blocks/*.block.json` — Merkle block headers
- `day/*.bin` — canonical day blob (for OTS)
- `day/*.bin.ots` — OTS proof
- `day/*.json` — human‑readable day record

# 2) Verify frames with real AEAD decryption (replay window=64)

## Development Commands

```bash
# Run full pipeline with real AEAD
make run
# 3) Batch facts into deterministic Merkle tree
# Run all tests with coverage
make test           # Quick test run
make test-cov       # With detailed coverage report

  --date 2025-10-13 \
make check          # Run linting + formatting + tests
make lint           # Lint with ruff
# 4) Anchor the day blob with OpenTimestamps
python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-13.bin
# CI simulation
make ci             # Run full CI checks locally

# Generate test vectors
make gen-vectors    # Regenerate deterministic AEAD vectors

# Cleanup
make clean          # Remove test artifacts
make clean-all      # Deep clean (including coverage reports)
```

## Manual step-by-step (M#1)

Run each pipeline step individually:

```bash
# 1) Generate framed telemetry (10 frames from pod-003)
python scripts/pod_sim/pod_sim.py \
  --framed \
  --device-id pod-003 \
  --count 10 \
  --out out/site_demo/frames.ndjson

# 2) Verify frames and extract facts (with replay window=64)
python scripts/gateway/frame_verifier.py \
  --in out/site_demo/frames.ndjson \
  --out-facts out/site_demo/facts \
  --device-table out/site_demo/device_table.json \
  --window 64
- **crypto_utils.py** — PyNaCl-based cryptographic primitives (M#3)
    - X25519 key exchange and HKDF-SHA256 derivation (RFC 5869)
    - XChaCha20-Poly1305 AEAD encryption/decryption
    - Ed25519 signatures
    - All operations via PyNaCl (libsodium) for consistency
    - References: ADR-001, ADR-005

- **frame_verifier.py** — Production framed ingest with real AEAD (M#3)
# 3) Batch facts into Merkle tree
    - **Real XChaCha20-Poly1305 decryption** with tag verification
    - AAD (Additional Authenticated Data) binding to header fields
python scripts/gateway/merkle_batcher.py \
    - Persistent device table for replay protection across restarts
  --out out/site_demo \
  --site an-001 \
  --date 2025-10-07 \
  --validate-schemas

# 4) Anchor the day blob
    - Day chaining via prev_day_root (32 zero bytes for genesis day)

# 5) Verify Merkle root and OTS proof
python scripts/gateway/verify_cli.py --root out/site_demo
```

## Quick demo (Milestone#0 — canonical batching)

Run the deterministic batch → anchor → verify loop with example facts:

```bash
# 1) Batch example facts → block header + day blob
python scripts/gateway/merkle_batcher.py \
  --facts toolset/unified/examples \
  --out out/site_demo \
  --site an-001 \
- **run_pipeline.sh** — End-to-end automation
    - One-command demonstration of complete workflow with real AEAD

# 2) Anchor the day blob (requires OpenTimestamps client)
python scripts/gateway/ots_anchor.py out/site_demo/day/2025-10-07.bin

# 3) Verify recomputed root matches and OTS proof verifies
python scripts/gateway/verify_cli.py --root out/site_demo
    - **Framed mode (`--framed`)**: emits encrypted `{hdr, nonce, ct, tag}` (M#3)
    - Uses XChaCha20-Poly1305 for encryption

## What's in here

- **crypto_test_vectors.json** — Deterministic AEAD test vectors (M#3)
    - XChaCha20-Poly1305 vectors for reproducible testing
    - Generated with PyNaCl bindings

- **frame_verifier.py** — M#1: Framed ingest + replay window protection
    - Parses NDJSON frames with header validation
    - Enforces replay window (default: 64, configurable)
    - Stub decryption (base64 JSON for M#1; real AEAD in M#2)
    - Emits canonical fact JSON files
- **device_table.schema.json** — Device table v1.0 (forward-only policy, ADR-006)
    - References: ADR-002 (Telemetry Framing, Nonce/Replay Policy)

    - X25519 + HKDF-SHA256 (RFC 5869) for key derivation
    - XChaCha20‑Poly1305 for AEAD (24-byte nonce)
    - Ed25519 for identity/config/firmware signatures
    - SHA‑256 for Merkle trees and hashing
    - **M#3**: Implemented with PyNaCl (libsodium)
- **CHANGELOG.md** — Keep a Changelog compliant version history
    - Outputs: blocks/*.block.json, day/*.bin, day/*.json
    - Schema validation with --validate-schemas
    - References: ADR-003 (Canonicalization, Merkle Policy)
    - AAD binding: dev_id || msg_type authenticated with ciphertext
    - Gateway replay window with configurable size (default: 64)
    - Persistent device table for state across restarts
- **ots_anchor.py** — OpenTimestamps integration
- **htmlcov/** — Test coverage reports
    - Stamps day.bin → day.bin.ots
    - Graceful fallback (placeholder) if OTS client missing
    - Day chaining via prev_day_root (32 zero bytes for genesis)

- **verify_cli.py** — Root recomputation and OTS verification
Run all tests with coverage:
pytest -q
```

# Quick test run

make test

# With detailed coverage report

make test-cov

- **Canonical JSON determinism**: Byte-identical output across runs

# Or directly with pytest

pytest --cov=scripts --cov-report=term-missing --cov-report=xml -v

### M#1 Tests (Framed Ingest)

**Current Status (M#3)**: 73 tests passing in 1.57s, 85% code coverage

- **Replay window**: Accepts increasing fc, rejects duplicates and out-of-window

### Test Suites

- **End‑to‑end pipeline**: pod_sim → frame_verifier → merkle_batcher → verify_cli

#### Cryptographic Primitives (`test_crypto_impl.py`)

- X25519: Key generation, shared secret agreement
- HKDF: Deterministic derivation per RFC 5869
- XChaCha20-Poly1305: Encrypt/decrypt round-trip, authentication failure detection
- Ed25519: Sign/verify signatures
- **8 tests, 99% coverage**
- Device table key lookup

#### Test Vectors (`test_crypto_vectors.py`)

- Deterministic AEAD vectors verified against PyNaCl
- Canonical JSON hashing with expected SHA-256 values
- Schema compliance for fact format
- **14 tests, 93% coverage**
- Tag verification

## Frame Format (M#3)

- Frame parsing: Valid/invalid structure, header validation
  Frames use NDJSON with JSON objects containing:
- End-to-end pipeline integration
- **3 tests, 97% coverage**

## Frame Format (M#1)

#### Security Testing (`test_framed_security.py`)

- **Ciphertext tampering**: Single-bit flip → authentication failure
- **Tag tampering**: Modified tag → rejection
- **AAD tampering**: Modified header → tag mismatch
- **Nonce validation**: Invalid nonce length → rejected
- **Unknown device**: Unprovisioned device → rejected
- **5 tests, 99% coverage**
  For M#1, frames use NDJSON with JSON objects containing:

#### Gateway Pipeline (`test_gateway_pipeline.py`)

- Canonical JSON determinism (sorted keys, no whitespace)
- Merkle root: empty, single, odd, power-of-2, order independence
  // 24 bytes: salt(8)||fc(8)||rand(8)
- Day chaining: prev_day_root linkage
  // XChaCha20-Poly1305 ciphertext
- **14 tests, 98% coverage**
  // 16 bytes: Poly1305 authentication tag

#### Merkle Reproducibility (`test_merkle_repro.py`)

- Deterministic root computation across runs
- Unicode handling, numeric precision
  **M#3 Production Behavior**:
- **12 tests, 99% coverage**
- `ct` field contains XChaCha20-Poly1305 encrypted JSON payload
- `tag` field is the Poly1305 authentication tag (verified on decrypt)
- `nonce` construction: 8-byte salt || 8-byte frame counter || 8-byte random
- AAD (Additional Authenticated Data): `dev_id || msg_type` binds header to ciphertext
- Device keys loaded from `device_table.json` (schema v1.0)
- Reject beyond window boundary
- Duplicate rejection across gateway restarts
- **3 tests, 99% coverage**
  "fc": 0,

#### Property-Based Testing (`test_tlv_properties.py`)

- TLV encoding round-trip with Hypothesis
- Robustness against arbitrary/truncated input
- Unknown tag handling
- **5 tests, 96% coverage**
  "flags": 0

### Coverage Report

},
**Overall**: 85% (1506 statements, 223 missed)
**M#1 Stub Behavior**:

| Module | Coverage | Missing Lines |
| ------ | -------- | ------------- |

- **M#0** ✅ (v0.0.1-m0, Oct 7 2025): Canonical schemas, deterministic batching, OTS anchoring
- **M#1** ✅ (v0.0.1-m1, Oct 12 2025): Frame verifier stub + pod simulator v2 → framed ingest
- **M#3** ✅ (v0.0.1-m3, Oct 13 2025): Real AEAD, PyNaCl migration, device table v1.0, 73 tests, 85% coverage
- **M#4** (planned): Gateway "Ledger" tab JSON output, outage logger, automated daily OTS anchor/upgrade
- **Future**: Key rotation workflows (ADR-001), operational hardening, performance optimization

**Note**: M#2 was an implementation phase (AEAD + test vectors) that was rolled into M#3 release.

- `ct` field contains base64-encoded JSON payload (no real encryption)
- **Python**: 3.11, 3.12, or 3.13 (CI tested on all three)
- **Required packages**: jsonschema, pynacl, pytest, pytest-cov, hypothesis

1. **Canonical JSON**: Sorted keys, UTF-8, no whitespace

- **Recommended**: [uv](https://github.com/astral-sh/uv) for fast dependency management

### Installation

2. **Hash-sorted leaves**: Merkle tree built from sorted leaf hashes (order-independent)
   Using **uv** (recommended for speed):

```bash
# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv pip install -r requirements.txt

# Install dev dependencies (linting, formatting)
uv pip install -r requirements-dev.txt
```

Using **pip**:
4\. **Day chaining**: Include prev_day_root (32 zero bytes for genesis day)
5\. **Consistent timestamps**: Use ISO 8601 UTC format

# Install dependencies

Running `merkle_batcher.py` twice on the same facts/ yields:

# Install dev dependencies

- Byte-identical day.bin (same SHA-256)

```

### CI/CD

The project uses GitHub Actions with `uv` for fast, reproducible builds:

- **Lint job**: ruff (linter) + black (formatter check)
- **Test job**: pytest with coverage on Python 3.11/3.12/3.13 matrix
- **Coverage**: Uploaded to Codecov (Python 3.13 only)

See `.github/workflows/ci.yml` for the full workflow.
- **M#3** ✅ (v0.0.1-m3): Production AEAD, PyNaCl migration, device table schema
- **Continuous**: Daily OTS anchor/upgrade automation, CLI polish

### Code Quality
- **Required packages**: pytest, jsonschema
- **Optional**: OpenTimestamps client (`ots`) for real proof anchoring
# Lint code with ruff
Install dependencies:
ruff check scripts/

# Auto-format with black
# Production dependencies
black scripts/

# Type checking (optional)
mypy scripts/gateway scripts/pod_sim

# Run all quality checks
make check    # lint + format + test
```

### Testing

```bash
# Run all tests
make test

# Run with coverage report
make test-cov

# Run specific test file
pytest scripts/tests/test_crypto_impl.py -v

# Run tests matching pattern
pytest -k "test_aead" -v

# Run with hypothesis verbose output
pytest --hypothesis-show-statistics
```

pip install -r requirements.txt

### Continuous Integration

Simulate CI locally:

```bash
make ci    # Runs lint, format check, and full test suite
pip install -r requirements-dev.txt

pip install uv
uv pip install -r requirements.txt
uv pip install -r requirements-dev.txt
```

## Development Workflow

### Linting and Formatting

Before committing code, run linting checks:

```bash
# Check code quality and formatting
make lint

# Auto-format code with black
make format

# Auto-fix linting issues
make lint-fix
```

The CI will automatically run these checks on every push/PR.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Pull request guidelines
- ADR process (Proposed → Accepted)
- Code style and testing requirements
- CI workflow and release process

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Citation

If you use this work in your research, please cite:

```bibtex
@software{trackone2025,
    author = {BILAL},
    title = {Track1: Ultra-Low-Power, Verifiable Telemetry (Barnacle Sentinel)},
    year = {2025},
    url = {https://github.com/bilalobe/trackone},
    version = {0.0.1-m1}
}
```

## Contact

- **Author**: BILAL
- **Repository**: https://github.com/bilalobe/trackone
- **Issues**: https://github.com/bilalobe/trackone/issues

For questions about the cryptographic design or OpenTimestamps integration, please open an issue or discussion on
GitHub.
