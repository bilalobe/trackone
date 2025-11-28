# Changelog

All notable changes to Track1 (Barnacle Sentinel) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.0.1-m5.1] - 2025-11-28

### Added
- Stationary OTS calendar sidecar image (`ots/calendar:latest`) built from
  `docker/calendar/` and used by the `ots-cal` and weekly ratchet workflows.
- Simple HTTP health endpoint on port `8468` (paths `/`, `/health`, `/ready`)
  to support deterministic readiness checks in CI and local testing.
- Build-provenance attestation for the stationary calendar image using
  `actions/attest-build-provenance`, stored alongside the image in GHCR for
  supply-chain verification.

### Changed
- Tightened `verify_cli` and `verify_ots` coupling to use `artifact_sha256`
  from `proofs/<day>.ots.meta.json`:
  - Enforce that `artifact` in meta resolves to the same `day.bin` used by the
    Merkle tree.
  - Enforce that `artifact_sha256` matches `sha256(day.bin)`.
  - Enforce that `ots_proof` in meta resolves to the `*.bin.ots` proof file.
  - Pass `artifact_sha256` into `verify_ots` so even stationary stubs must
    match the recorded artifact hash.
- Updated weekly ratchet workflow to:
  - Build and publish the stationary calendar image to GHCR.
  - Attest calendar image provenance for traceability.
  - Start a local calendar sidecar and prefer it in `OTS_CALENDARS`.
  - Fail (in strict mode) when real-OTS runs are incomplete or fully skipped,
    instead of silently treating them as success.

## [0.0.1-m5] - 2025-11-18

### Added

- **Parallel anchoring support (ADR-015)**: TrackOne now supports optional RFC 3161 TSA timestamps and peer co-signatures alongside OpenTimestamps
  - `run_pipeline_demo.py` supports `--tsa-url`, `--peer-config` flags to enable parallel anchoring
  - `verify_cli.py` supports `--verify-tsa`, `--verify-peers` with strict/warn modes
  - TSA artifacts (`*.tsq`, `*.tsr`, `*.tsr.json`) and peer signatures (`*.peers.json`) stored under `out/site_demo/day/`
  - Pipeline manifest tracks TSA and peer artifacts for automated verification discovery
  - Demo peer configuration at `toolset/demo_peer_config.json` for local testing
  - New exit codes: 5=TSA failed (strict), 6=peer failed (strict)
  - Documentation updates: README, `docs/ots-verification.md`, ADR-015
- OTS verification workflow installs the `opentimestamps-client` (`ots` CLI) so verification doesn't skip when the binary is missing. `STRICT_VERIFY=1` is enforced on `main`.
- Stationary OTS configuration knobs documented in `README.md` and `docs/ots-verification.md`:
  - `OTS_STATIONARY_STUB` to toggle stub vs real-client behavior.
  - `OTS_CALENDARS` to select calendar URLs (local real calendar first, then public if desired).
  - `RUN_REAL_OTS` to gate slow, real-calendar integration tests.
- New tox env `ots-cal` and GitHub Actions workflow `.github/workflows/ots-cal.yml` to run `real_ots` tests against a local OTS calendar container in CI.

### Changed

- CI lint job now runs only lint/type/security tox envs instead of `tox -p`, preventing accidental test execution and reducing runtime.
- OTS verification workflow is now self-contained: it generates pipeline artifacts within the same job before verification, eliminating cross-workflow race conditions.
- Default test runs now use a stationary OTS stub (`OTS_STATIONARY_STUB=1` via `tests/conftest.py`), eliminating slow and flaky calls to public OTS calendars while still enforcing `ots_meta` + artifact hashing.
- Tightened `verify_cli` and `verify_ots` coupling to use `artifact_sha256`
  from `proofs/<day>.ots.meta.json`:
  - Enforce that `artifact` in meta resolves to the same `day.bin` used by the
    Merkle tree.
  - Enforce that `artifact_sha256` matches `sha256(day.bin)`.
  - Enforce that `ots_proof` in meta resolves to the `*.bin.ots` proof file.
  - Pass `artifact_sha256` into `verify_ots` so even stationary stubs must
    match the recorded artifact hash.
- Updated weekly ratchet workflow to start the local calendar, prefer it in
  `OTS_CALENDARS`, and fail (when strict) on incomplete real-OTS runs.

### Removed

- CI no longer uploads `pipeline-day` artifacts from the pipeline job since OTS verification now generates and consumes artifacts locally.

  - New `conftest.py`: Shared fixtures for workspace, sample facts, and device tables
- **Test run summary**: 182 passed, 4 skipped (spot-check run: pytest full suite)

### Changed

- CI uses a matrix for tests on Python 3.12, 3.13, 3.14 and a separate meta job (lint/type/readme/precommit/security) on 3.14.
- Single Makefile targets now delegate to tox (tests, coverage, lint/type, pipeline, OTS, bench).
- tox uses `tox-uv` for faster environment creation and installs; caching added for pip, uv, pre-commit, and tox venvs.
- README structure simplified; pre-commit section updated.
- OTS anchoring now attempts an immediate best-effort `ots upgrade` after stamping; verification script also runs `ots upgrade` before parsing heights.
- OTS verification can auto-squash `.ots.bak` into `.ots` when valid (configurable) and is non-fatal in non-strict mode when proofs are placeholders.
- **Test suite**: Expanded from 73 → 182 tests after verify_cli fix for placeholder handling and comprehensive new coverage
- **Test coverage by module**:
  - `ots_anchor.py`: 0% → 95% (stamping, CLI, fallbacks)
  - `pod_sim.py`: 26% → 81% (fact generation, TLV, device tables, CLI)
  - `frame_verifier.py`: 79% → 82% (added edge case handling)
  - `verify_cli.py`: 75% → 78% (added error path coverage)
  - `merkle_batcher.py`: 90% (stable, high coverage)
  - `crypto_utils.py`: 97% (stable, near-complete)
- **Test suite organization**: Centralized fixtures in conftest.py, parametrized tests for better coverage
- **Test stability**: Fixed flaky assertions (timestamp formats, nonce randomness)
- **Documentation**: Results section in TeX report includes M#4 milestone verification details
    - Block height: 919384
    - Block hash: `00000000000000000000b36d7b88a2e781f65619746bc238d4cfde8555f13733`
    - Merkle root: `166c8fe05f6071d8a29145c4e52c039159c699f3278c45d1c3107503b59c8047`
    - Artifact SHA256: `4778cddcf437f0b0ac8cd62fef3b89909bd6f4a8fd9590ac6e4a70e4fded5f60`
- Relocated directory fixtures that are only used by integration and end-to-end suites to module-scoped fixtures so unit-test collection is faster and test isolation is improved:
  - `temp_workspace` and related helpers moved to `tests/integration/fixtures/helpers.py` (module-scoped for integration tests).
  - `temp_dirs` moved to the e2e module scope (e.g. `tests/e2e/conftest.py`) so framed/e2e tests share a stable workspace layout without polluting unit test collection.
- Deprecated the global aggregation of directory fixtures from `tests/fixtures/common_fixtures.py`; directory fixtures are no longer implicitly provided to all test packages.

### Fixed

- Bench tox env now includes `pytest-benchmark` and recognizes benchmark CLI flags.
- OTS verification helper script passes `bitcoind` flags safely and handles multiple proof shapes.
- CI replaces external Codecov upload with artifact upload of coverage.xml per env.
- **test_end_to_end_pipeline**: Now passes with OTS placeholder files (exit code 4 → 0)
- **pod_sim tests**: Aligned with actual implementation (timestamp formats, build_nonce, device table behavior)
- **OTS tests**: Tolerate both binary OTS files and text placeholders for cross-environment compatibility

### Verification

Successfully verified OTS anchoring using local Bitcoin Core node (headers-only mode):

```bash
ots verify out/site_demo/day/2025-10-07.bin.ots
# Success! Bitcoin block 919384 attests existence as of 2025-10-16 IST

bitcoin-cli getblockheader $(bitcoin-cli getblockhash 919384) | jq -r .merkleroot
# 166c8fe05f6071d8a29145c4e52c039159c699f3278c45d1c3107503b59c8047

python scripts/gateway/verify_cli.py --root out/site_demo --facts out/site_demo/facts
# OK: root matches and OTS verified
```

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
