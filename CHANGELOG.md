# Changelog

All notable changes to Track1 (Barnacle Sentinel) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MIT License for open source distribution
- Citation information in README.md
- Contact section with GitHub links
- **CI lint step** with ruff and black for code quality
- `requirements-dev.txt` for development dependencies
- `make format` and `make lint-fix` targets for auto-fixing issues

### Changed

- CI workflow now runs lint checks before tests
- Makefile lint target improved with better error messages

### Planned for M#2

- Real AEAD encryption (XChaCha20-Poly1305) with test vectors
- Enhanced replay window enforcement with persistent state
- Device table key lookup integration
- Additional crypto test coverage

### Planned for M#3

- Gateway "Ledger" tab JSON output
- Outage logger
- Daily OTS anchor/upgrade automation

## [0.0.1-m1] - 2025-10-12

### Added - Milestone #1: Framed Telemetry Ingest

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

### Enhanced

- **merkle_batcher.py**: Added detailed docstrings explaining canonicalization and determinism
- **verify_cli.py**: Updated documentation for --facts argument usage
- **ots_anchor.py**: Added fallback OTS placeholder for environments without OTS client
- **pod_sim.py**: Refactored emit_framed() to output header as dict (not base64)
- **Makefile**: Added milestone-agnostic targets (run, run-m1, run-m0)

### Documentation

- **README.md**: Updated with M#1 quick start, framed ingest explanation, and architecture overview
- **ADR-002**: Telemetry Framing, Nonce/Replay Policy (referenced in frame_verifier.py)
- **Module docstrings**: Added comprehensive docstrings to all gateway scripts
- **Inline comments**: Added maintainability constants (DEFAULT_REPLAY_WINDOW, etc.)

### Fixed

- Frame format alignment between pod_sim.py and frame_verifier.py
- verify_cli.py argument handling for --facts parameter
- Test fixtures and helper functions for framed ingest testing

## [0.0.1-m0] - 2025-10-07

### Added - Milestone #0: Foundation

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

### Infrastructure

- **pyproject.toml**: Project metadata and dependencies
- **requirements.txt**: Python dependencies (jsonschema, pytest)
- **Makefile**: Automation targets for M#0 and M#1 workflows
- **.gitignore**: Ignore /out directory and build artifacts
- **CI**: GitHub Actions workflow for pytest on pull requests
- **CONTRIBUTING.md**: Guidelines for PRs, ADRs, CI, releases

### Documentation

- **README.md**: Quick start demos, design decisions, roadmap
- **adr/README.md**: ADR index and template
- **LaTeX manuscript structure**: Initial src/main.tex with section includes

## [0.0.0] - 2025-09-15

### Added

- Initial repository structure
- Project planning documents
- Milestone requirements specification
