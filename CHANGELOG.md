# Changelog

All notable changes to Track1 (Barnacle Sentinel) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.4] - 2026-02-26

### Added
- Pre-commit hook: `scan-embedded-proofs` to detect suspicious embedded OTS proof blobs in staged JSON files.
- Tests: added coverage for the `trackone_core` packaged/native layouts and for behavior when the native extension is missing.
- Anchoring policy/config surface for ADR-015:
  - Added root `anchoring.toml` with `[ots]`, `[tsa]`, `[peers]`, `[policy]`.
  - Added `scripts/gateway/anchoring_config.py` with deterministic precedence (`defaults < file < env < CLI`) and `warn|strict` overall status reduction.
  - Added `tests/unit/gateway/test_anchoring_config.py` for precedence and policy behavior.
- Verifier/pipeline structured status outputs:
  - `verify_cli.py` now supports `--json`, `--config`, and `--policy-mode`.
  - `run_pipeline_demo.py` now records per-channel status (`ots`, `tsa`, `peers`) and policy outcome in the pipeline manifest.
  - CI now publishes verifier summary output (`out/site_demo/day/verify_summary.json`) in OTS verification workflow artifacts.

### Changed
- Packaging (maturin/PyO3): the native extension module is now built as `trackone_core._native` with a small Python wrapper package at `trackone_core/`. This allows setting `python-source` without breaking `maturin pep517 write-dist-info` in CI while keeping `import trackone_core` stable.
- Python wheel contents: ship `trackone_core` bindings only (no `scripts/` tooling package included in the wheel).
- Tox/uv orchestration hardening:
  - Default tox envs now run via `uv-venv-lock-runner` with `uv_sync_locked=true` to keep installs aligned to the committed `uv.lock`.
  - Shared tox `setenv` now carries `UV_CACHE_DIR={toxworkdir}/.uv-cache` so wheel and test envs use a writable, deterministic cache path.
  - `test-wheel` and `wheel-resolve` now declare `depends = maturin-build` so wheel tests can be run directly without manual pre-steps.
  - Tool-only envs (`lint`, `format`, `type`, `security`) now use `package = skip` to avoid unnecessary package build/install during checks.
- CI dependency bootstrap is again extras-driven (`pip install -e ".[ci]"`, with `.[ci,test]` / `.[ci,test,security]` where needed), keeping Dependabot-managed constraints in `pyproject.toml` authoritative.
- Day commitment artifact naming migrated from legacy `day/YYYY-MM-DD.bin` to `day/YYYY-MM-DD.cbor`:
  - `merkle_batcher.py` now writes `*.cbor`, `*.json`, and `*.cbor.sha256`.
  - `verify_cli.py`, `run_pipeline_demo.py`, `run_pipeline.sh`, and workflows now consume/upload `.cbor` artifacts.
  - Documentation and fixtures updated to reflect `.cbor`/`.cbor.ots`.
- ADR-039 commitment authority migration is now active:
  - Added deterministic CBOR canonicalization in `crates/trackone-ledger/src/c_cbor.rs` and Python helper `scripts/gateway/canonical_cbor.py`.
  - `frame_verifier.py` now emits authoritative `facts/*.cbor` with JSON projections.
  - `merkle_batcher.py` and `verify_cli.py` now recompute commitments from `facts/*.cbor` and reject JSON-only fact directories.
  - `verify_cli.py` now validates `day/<day>.cbor` by recanonicalizing `day/<day>.json` into deterministic CBOR and byte-comparing.
  - Deterministic map-key ordering tightened to RFC 8949 Section 4.2.1 for text keys (UTF-8 length, then lexicographic bytes), with Rust/Python parity tests.
- Cargo workspace internal dependencies now resolve to local path crates (`trackone-core`, `trackone-ledger`, `trackone-constants`) to keep alpha.4 implementation coherent across crates.
- Policy behavior tightened:
  - `verify_cli --require-ots` now enforces OTS validation even when config disables OTS.
  - `run_pipeline_demo --skip-ots/--skip-tsa/--skip-peers` now propagates to `verify_cli` execution, preventing policy/config mismatch during post-run verification.

### Fixed
- Python package imports: `trackone_core` now gracefully handles missing native extension (`_native` module) by wrapping imports in try/except blocks and providing fallback stubs when the Rust extension is not built or installed.
  - `trackone_core/__init__.py` wraps `_native` import and provides `None` fallback for `Gateway`, `GatewayBatch`, `PyRadio`, and `__version__`.
  - `trackone_core/crypto.py`, `ledger.py`, `merkle.py`, `ots.py` now catch `ImportError` when importing from `_native` and raise a clear `ImportError` on attribute access time (via `__getattr__`).
  - `scripts/gateway/verify_cli.py` and `merkle_batcher.py` suppress mypy type errors for `trackone_core = None` assignments with `# type: ignore[assignment]`.
- Tests: `tests/unit/trackone_core/test_native_missing.py` now forces `_native` import failure via negative `sys.modules` caching so it remains valid even in environments where the native extension is installed.
- Avoided hard import failure in `verify_cli.py` when `pynacl` is unavailable by lazy-loading peer verification helpers.
- Wheel tox env reliability: fixed `No module named pip` failures by bootstrapping pip with `python -m ensurepip --upgrade` before `python -m pip ...` commands in `test-wheel` and `wheel-resolve`.

### Integration Notes
- `tox -e pipeline` was executed successfully on 2026-02-23 and completed artifact generation.
- Observed gap: freshly stamped OTS proofs can still be incomplete at immediate verification time (`verify_cli` exit code `4`, `ots-verification-failed`) because calendar attestations are pending Bitcoin confirmation.
- Current behavior remains non-fatal in `warn` mode (pipeline prints warning and exits success). Use strict policy and/or delayed upgrade/verification if hard-pass OTS verification is required in the same run.
- ADR-039 is now accepted for the `0.1.0-alpha.4` track. Implementation start state:
  - Canonical CBOR profile is implemented in `crates/trackone-ledger/src/c_cbor.rs` and surfaced through `trackone-gateway` PyO3 bindings.
  - Pipeline/verifier commitment authority now uses deterministic CBOR bytes (`facts/*.cbor`, `day/*.cbor`) with JSON projections for human/audit readability.
  - `trackone-gateway/src/ots.rs` remains a placeholder boundary and is unchanged by this migration.
- 2026-02-26 local validation notes:
  - Targeted ADR-039 suites passed (`tests/unit/gateway/test_merkle_batcher.py`, `tests/integration/test_merkle_batcher.py`, `tests/integration/test_verify_cli*.py`, `tests/integration/test_replay_merkle_integration.py`).
  - `tox` execution is currently blocked in this environment by network-restricted dependency resolution for `maturin` (PyPI DNS unavailable).
  - Broader `tests/unit/gateway` collection is additionally blocked here where `pynacl` is unavailable.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- Gateway Rust extension API improvements (`crates/trackone-gateway`):
  - Exposed `Gateway`, `GatewayBatch`, and `PyRadio` in the `trackone_core` PyO3 module.
  - Exposed `merkle_root_*` helpers implementing the ADR-003 Merkle policy (via `crates/trackone-ledger`).
  - Exposed `trackone_core.ledger` helpers for canonical JSON and canonical `day.bin`/block-header stamping.
- Ledger helpers (`crates/trackone-ledger`):
  - Canonical JSON encoding and ADR-003 Merkle policy (single-sourced for batching + verification).
  - Block header + day record helpers, including canonical `day.bin` JSON bytes.
- Pod firmware helpers (`crates/trackone-pod-fw`):
  - Added `Pod` helper for constructing + encrypting facts via `trackone-core::frame`.
  - Added `CounterNonce24` counter-based nonce generator (24-byte, XChaCha20-Poly1305).
  - Added small firmware utilities (`hal`, `power`, `stress`) promoted from the legacy bench prototype.
- Workspace constants (`crates/trackone-constants`):
  - Added `AEAD_NONCE_LEN` and `AEAD_TAG_LEN` for shared sizing policy.

### Documentation
- Added the bench topology document: `docs/bench-network.md`.
- Added firmware notes and patterns: `docs/pod-fw.md`.

### Changed
- Python pipeline hardening:
  - `merkle_batcher.py` now prefers Rust-ledger stamping when `trackone_core` is available (canonical block header + `day.bin` bytes).
  - `verify_cli.py` now validates that `day.bin` is canonical (ADR-003) and that its embedded `day_root` matches the recorded Merkle root (gapless anchoring contract).
- Bumped workspace crates to `0.1.0-alpha.3` (per ADR-035 umbrella versioning):
  - `trackone-gateway` to `0.1.0-alpha.3` - Gateway API + Merkle helpers (delegating to `trackone-ledger`) (see `crates/trackone-gateway/CHANGELOG.md`)
  - `trackone-core` to `0.1.0-alpha.3` - Version alignment + constants wiring (see `crates/trackone-core/CHANGELOG.md`)
  - `trackone-pod-fw` to `0.1.0-alpha.3` - Pod helpers + nonce generator (see `crates/trackone-pod-fw/CHANGELOG.md`)
  - `trackone-constants` to `0.1.0-alpha.3` - Added shared AEAD sizing constants (see `crates/trackone-constants/CHANGELOG.md`)
  - `trackone-ledger` to `0.1.0-alpha.3` - Canonical JSON + Merkle + day/block record helpers (see `crates/trackone-ledger/CHANGELOG.md`)

### Removed
- Retired the legacy `crates/trackone-bench` prototypes after promoting the useful utilities and docs.

## [0.1.0-alpha.2] - 2026-01-22

### Added
- Dependency management tooling and workflows:
  - Added focused Python extras (`lint`, `type`, `security`, `anchoring`) and kept `dev` as a convenience union.
  - Added `ci` extra to bootstrap tox tooling in GitHub Actions.
  - Added `make export-requirements` to export pinned `out/requirements*.txt` from `uv.lock` for interoperability.
  - Weekly ratchet now runs a scheduled `pip-audit` over the full tooling + test install (lock-enforced).

- `trackone-core` protocol hardening and schema evolution (see `crates/trackone-core/CHANGELOG.md` for full details):
  - **BREAKING**: `PodId` expanded from `u32` to `[u8; 8]` (with `From<u32>` for backward compatibility)
  - **BREAKING**: `FactPayload` restructured; `Fact` gained time semantics fields
  - Added provisioning module for device identity and chain of trust
  - Added deterministic CBOR encoding for cryptographic commitments
  - Added environmental sensing types aligned with OGC SensorThings
  - Added serialization benchmarks and production safety checks

### Changed
- Bumped workspace crates to `0.1.0-alpha.2` (per ADR-035 umbrella versioning):
  - `trackone-core` to `0.1.0-alpha.2` - **Major changes**: schema evolution, provisioning records, CBOR encoding, breaking API changes (see `crates/trackone-core/CHANGELOG.md`)
  - `trackone-gateway` to `0.1.0-alpha.2` - Minor changes: version alignment, updated `trackone-core` dependency (still scaffolding; see `crates/trackone-gateway/CHANGELOG.md`)
  - `trackone-pod-fw` to `0.1.0-alpha.2` - Minor changes: version alignment, updated `trackone-core` dependency (still skeleton; see `crates/trackone-pod-fw/CHANGELOG.md`)
  - `trackone-constants` to `0.1.0-alpha.2` - Minor changes: version alignment only (see `crates/trackone-constants/CHANGELOG.md`)

- CI/tox dependency resolution is now `uv.lock`-first:
  - Tox envs (lint/type/security/tests) install only via `pyproject.toml` extras and the committed `uv.lock`.
  - Removed reliance on root `requirements*.txt` and `ci-requirements.txt` (CI installs `.[ci]` instead).
- OTS calendar integration testing:
  - Tightened `tox -e ots-cal` to only run `tests/integration/test_ots_integration.py`.
  - Made `ots-cal` self-contained: it can start/stop a local `trackone_ots_calendar` container from the GHCR `ots-calendar` image (matching Weekly Ratchet).
- Security scanning:
  - Bandit suppressions updated to supported `# nosec Bxxx` form to avoid noisy "Test in comment" warnings.

### Documentation
- Updated ADR-005 and ADR-009 to reflect lockfile-first dependency management and the new security/tooling workflow
- Updated README and CONTRIBUTING to recommend lockfile-first installs via focused extras (or `make dev-setup`)
- Added per-crate CHANGELOGs for independent consumability (ADR-035)
- Created `justfile` with correct feature combinations for CI/development


## [0.1.0-alpha.1] - 2025-12-12

### Added
- Implemented the first usable skeleton of the `trackone-core` Rust crate (ADR-017 follow-up), intended as the shared protocol/crypto layer for both gateway and pod:
  - `types` module with `PodId`, `FrameCounter`, `Fact`, `FactPayload`, and a bounded `EncryptedFrame<N>` using `heapless::Vec` for `no_std`-friendly ciphertext storage.
  - `crypto` module exposing `AeadEncrypt`/`AeadDecrypt` traits and a `SymmetricKey` type, plus a feature-gated `dummy-aead` XOR-based implementation for tests and examples.
  - `frame` module wiring postcard serialization to AEAD, with `make_fact`, `encrypt_fact`, and `decrypt_fact` helpers that implement the canonical wire format: postcard-encoded `Fact` encrypted into an `EncryptedFrame`.
  - `merkle` module (behind the `gateway` feature) providing SHA-256 based `hash_frame` and `merkle_root` helpers for gateway-side batching and anchoring.
- Promoted `MAX_FACT_LEN` to a workspace-level constants crate `crates/trackone-constants` and re-exported it from `trackone-core` as `trackone_core::MAX_FACT_LEN` so all crates share the canonical serialized `Fact` size (256 bytes).
- Added a unit test ensuring a representative `Fact` serializes within `MAX_FACT_LEN`.
- Workspace wiring and package metadata updates:
  - Added `crates/trackone-constants` to the workspace and re-exported `MAX_FACT_LEN` from `trackone-core`.
  - Set workspace-managed versioning so all member crates inherit `0.1.0-alpha.1` via `version.workspace = true`.
  - Set `trackone-core` `package.repository` to `https://github.com/bilalobe/trackone` for crates.io metadata.
- Crate wiring and build hygiene:
  - `trackone-gateway` now depends on `trackone-core` with `features = ["gateway"]` so gateway builds enable Merkle helpers and `std`.
  - `trackone-pod-fw` now depends on `trackone-core` with `default-features = false` so firmware builds opt out of `dummy-aead` and `std` by default.
  - Moved the release profile (`[profile.release]`) to the workspace root `Cargo.toml` and removed per-crate profile definitions to avoid profile duplication warnings.
- Documentation and developer ergonomics:
  - Added concise per-crate README files (`trackone-core`, `trackone-gateway`, `trackone-pod-fw`, `trackone-constants`) describing responsibilities, dependencies, and including Mermaid `C4Context` diagrams for quick architecture context.

### Changed
- Versioning: standardized workspace-managed versioning; the workspace package version is `0.1.0-alpha.1` and member crates inherit it via `version.workspace = true`.
- Feature model: `trackone-core` is `no_std`-first with an opt-in `std` feature. `gateway` pulls in `sha2` and `std`. The `dummy-aead` feature remains enabled by default for development/testing convenience; production firmware should build with `default-features = false`.
- `frame` helpers updated to use `MAX_FACT_LEN` (workspace constant) instead of local magic numbers; error reporting refined (SerializeError, DeserializeError, SerializeBufferTooSmall, CiphertextTooLarge, CryptoError).
- Build profiles: release profile options (LTO, opt-level, panic) are now centralized at the workspace root to ensure consistent release builds and silence duplicate-profile warnings.
- Documentation: per-crate README files now provide classic architecture overviews and embedded Mermaid diagrams; `trackone-core` re-exports `MAX_FACT_LEN` for consumer convenience.
- Documentation: reworded per-crate README files to a classic architecture style (Overview / Purpose / Responsibilities), removing the previous "C4 level" phrasing while keeping the Mermaid diagrams for visual context.

### Notes
- `MAX_FACT_LEN` is a policy knob (256 bytes) chosen for current payloads. If future `FactPayload` variants grow (e.g., diagnostic blobs), increase the constant and add or update tests to assert the new maximum.
- Keeping `dummy-aead` enabled by default is a development convenience; firmware builds must opt out via `default-features = false` to avoid shipping the dummy AEAD.


## [0.0.1-m6] - 2025-12-01

### Added
- Introduced a Rust workspace to host shared core logic and gateway/pod crates (ADR-017). These crates are **foundational only** in this pre-release phase; the production gateway and pipeline remain driven by the existing Python implementation:
  - `crates/trackone-core` — platform-agnostic Rust crate for protocol and crypto primitives; intended home for Merkle, crypto, and protocol invariants used by both gateway and pod (not yet wired into the live pipeline).
  - `crates/trackone-gateway` — Rust `cdylib` crate exposed to Python via PyO3 and built with `maturin`; will gradually wrap `trackone-core` and surface optimized operations to Python callers.
  - `crates/trackone-pod-fw` — Rust crate for future pod/firmware logic, depending on `trackone-core`.
- Added basic Rust workspace tooling:
  - `make cargo-test`, `make cargo-check`, `make cargo-fmt`, `make cargo-clippy` for running tests, checks, formatting, and clippy across the Rust workspace.
  - `tox` environment `maturin-build` to build wheels via `maturin`, and a `build-wheel` GitHub Actions job that uses `maturin build --manifest-path crates/trackone-gateway/Cargo.toml` to produce the PyO3-backed wheel artifact.

### Changed
- Switched Python packaging backend from `hatchling` to `maturin` in `pyproject.toml`, keeping the existing `scripts` package as the Python surface while letting `maturin` build the Rust-backed wheel.
- Upgraded PyO3 to `0.27` and updated PyO3/PyO3-macros usage in `crates/trackone-gateway` to match the newer API surface (pymodule/submodule registration). This enables building the extension against Python 3.14 while still treating the Rust layer as an internal implementation detail.
- CI: standardized jobs that build or install the Rust extension (`lint`, `pipeline`, and `build-wheel`) to use Python 3.14 so tox envs and maturin build steps run consistently across the matrix.
Confirmed that we remain in the 0.0.x pre-release era: 0.0.1-m6 formalizes the Rust workspace, PyO3 0.27, and Python 3.14 CI as internal scaffolding; CLI/API behavior is unchanged.
- Updated README and ADR-017 to document the Rust workspace layout, crates, and phased migration plan from Python-only implementations to Rust-backed primitives.


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
