# Changelog

All notable changes to Track1 (Barnacle Sentinel) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **QIM-A watermarking infrastructure** (ADR-007)
    - QIM module stubs (embed, detect, config) for biometric time-series authenticity
    - Gateway integration module (qim_verifier.py)
    - Band-pass filtering for bio-signal frequency band (~1/200 to 1/10 Hz)
    - Configuration with operating parameters (Δ/σ, block_sec, detection thresholds)
    - Test stubs for QIM modules (test_qim_embed.py, test_qim_detect.py)
- **git-cliff configuration** for automated changelog generation
    - Conventional commit parsers (feat → Added, fix → Fixed, etc.)
    - Support for milestone-based tags (v0.0.1-m3, v0.0.1-m4, etc.)
    - Keep a Changelog format with SemVer compliance
- **Makefile targets** for QIM workflow
    - `make qim-notebook`: Validate QIM-A notebook (for M#5)
    - `make test-qim`: Run QIM-specific tests
- Gateway "Ledger" tab JSON output
- Outage logger
- Daily OTS anchor/upgrade automation

## [0.0.1-m3] - 2025-10-12

### Added

- **Status badges** in README.md: CI, codecov, Python 3.11+, MIT License
- **Enhanced Makefile** with comprehensive targets:
    - `make install`, `make dev-setup`, `make gen-vectors`, `make test-cov`, `make clean-all`, `make check`, `make ci`,
      `make watch`
- **Python version matrix in CI**: Tests against Python 3.11, 3.12, and 3.13
- **Deterministic AEAD test vectors**:
    - `scripts/dev/gen_aead_vector.py` (ChaCha) and unified `crypto_test_vectors.json`
    - Enabled `TestDeterministicAEADVectors` including XChaCha vectors
- **Property-based tests** with Hypothesis (TLV round-trip + robustness)
- **Replay window edge tests** (within window, beyond window, duplicate across restart)
- **ADR-005**: PyNaCl migration plan
- **Development workflow docs** in README
- **Device table schema v1.0**: Forward-only policy (ADR-006), requires `_meta.version = "1.0"`, `salt8` (8 bytes,
  base64), and `ck_up` (32 bytes, base64). Per-device entries and `_meta` are strict (`additionalProperties: false`)

### Changed

- **Real AEAD encryption**: Runtime XChaCha20-Poly1305 (24-byte nonce) in verifier/simulator
- **ReplayWindow**: Initializes from persisted device_table
- **frame_verifier.py**: Type hints, docs, decode_tlv cleanup
- **crypto_utils.py**: HKDF-SHA256 via RFC 5869; removed `cryptography` dependency
- **Auto-formatting**: black + ruff; standardized imports and typing
- **CI workflow**: Split jobs and Python matrix (3.11/3.12/3.13)
- **Pipeline**: Updated banner/wording to reflect device table schema v1.0
- **Makefile**: Simplified to a single `run` pipeline (removed M#0/M#1 targets)

### Removed

- **ChaCha20-Poly1305** (12-byte nonce) in runtime code
- **salt4** everywhere (no fallback/derivation)
- **cryptography** library dependency

### Fixed

- Replay window persistence bug
- Frame counter generation in tests (batching)
- AEAD decrypt failures (IETF variants parameter order)
- HKDF implementation correctness (RFC 5869)
- Linting issues: variable rename, imports, typing

### Migration Notes

For users with existing M#1/M#2 device tables:

```bash
# Archive old table
mkdir -p archive/m2
cp device_table.json archive/m2/

# Regenerate for M#3
python provision_devices.py --reset --version 1.0

# Verify schema compliance
python -m jsonschema -i device_table.json toolset/unified/schemas/device_table.schema.json
```

## [0.0.1-m1] - 2025-10-12

### Added

- **frame_verifier.py**: Parses framed NDJSON telemetry, enforces replay window (stub decrypt for M#1)
    - Validates frame structure with header fields: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
    - Implements replay protection with configurable window size (default: 64)
    - Stub decryption (base64-encoded JSON payload)
    - Emits canonical fact JSON files
- **pod_sim.py --framed**: Generates framed telemetry records
    - Outputs NDJSON with {hdr, nonce, ct, tag} fields
    - Optional plain facts output for cross-checking
- **run_pipeline.sh**: End-to-end M#1 pipeline script
    - Integrates: pod_sim → frame_verifier → merkle_batcher → ots_anchor → verify_cli
    - Single command demonstration of complete workflow
- **Tests for framed ingest**:
    - test_accept_increasing_fc: Validates monotonic frame counter acceptance
    - test_reject_duplicate_and_out_of_window: Ensures replay protection
    - test_end_to_end_pipeline: Complete workflow validation
    - test_parse_frame_valid/invalid: Frame parsing edge cases
- **README.md**: Updated with M#1 quick start, framed ingest explanation, and architecture overview
- **ADR-002**: Telemetry Framing, Nonce/Replay Policy (referenced in frame_verifier.py)
- **Module docstrings**: Added comprehensive docstrings to all gateway scripts
- **Inline comments**: Added maintainability constants (DEFAULT_REPLAY_WINDOW, etc.)
- **Makefile**: Added milestone-agnostic targets (run, run-m1, run-m0)

### Changed

- **merkle_batcher.py**: Added detailed docstrings explaining canonicalization and determinism
- **verify_cli.py**: Updated documentation for --facts argument usage
- **ots_anchor.py**: Added fallback OTS placeholder for environments without OTS client
- **pod_sim.py**: Refactored emit_framed() to output header as dict (not base64)

### Fixed

- Frame format alignment between pod_sim.py and frame_verifier.py
- verify_cli.py argument handling for --facts parameter
- Test fixtures and helper functions for framed ingest testing

## [0.0.1-m0] - 2025-10-07

### Added

- **Canonical schemas**: fact.schema.json, block_header.schema.json, day_record.schema.json
- **merkle_batcher.py**: Deterministic Merkle tree builder
    - Reads facts/*.json → writes blocks/*.json + day/day.bin
    - Canonical JSON (sorted keys, UTF-8, no whitespace)
    - Hash-sorted Merkle leaves for order independence
    - Day chaining via prev_day_root (32 zero bytes for day 1)
    - Schema validation with --validate-schemas flag
- **ots_anchor.py**: OpenTimestamps integration
    - Stamps day.bin → day.bin.ots
    - Graceful fallback for missing OTS client
- **verify_cli.py**: Root recomputation and OTS verification
    - Recompute Merkle root from facts/
    - Compare against block header and day record
    - Verify OTS proof
- **Example facts**: 5 example fact files (pods 101-104) in unified format
- **ADRs**:
    - ADR-001: Cryptographic Primitives (X25519, HKDF, XChaCha20-Poly1305, Ed25519)
    - ADR-003: Canonicalization, Merkle Policy, Daily OTS Anchoring
- **Tests**:
    - Canonical JSON determinism
    - Merkle root computation (empty, single, odd, power-of-2, order independence)
    - Schema validation
    - Day chaining
    - End-to-end batch/verify workflow
- **pyproject.toml**: Project metadata and dependencies
- **requirements.txt**: Python dependencies (jsonschema, pytest)
- **Makefile**: Automation targets for M#0 and M#1 workflows
- **.gitignore**: Ignore /out directory and build artifacts
- **CI**: GitHub Actions workflow for pytest on pull requests
- **CONTRIBUTING.md**: Guidelines for PRs, ADRs, CI, releases
- **README.md**: Quick start demos, design decisions, roadmap
- **adr/README.md**: ADR index and template
- **LaTeX manuscript structure**: Initial src/main.tex with section includes

## [0.0.0] - 2025-09-15

### Added

- Initial repository structure
- Project planning documents
- Milestone requirements specification
