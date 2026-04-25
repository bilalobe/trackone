# Changelog

All notable changes to TrackOne will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `trackone_core.admission` now provides package-level gateway admission-state
  and rejection-audit helper shapes for rejection records, rejected-frame
  hashing, audit day labels, and non-secret device-table state updates.
- Public commitment-vector manifest schema plus vector-corpus README documenting the CBOR encoding profile, fact/day CBOR shapes, and ADR-003 Merkle policy needed by source-independent verifiers.

### Changed
- The local verification/export refusal gate now lives on
  `trackone_core.verification.local_verification_failure`, so evidence export,
  the demo runner, and compatibility imports share one package-level
  local-integrity vocabulary.
- `provisioning_records.py` now delegates provisioning-bundle construction and
  shape validation to `trackone_core.sensorthings`, while retaining sidecar
  checks, schema validation, and file writing in the CLI wrapper.
- `frame_verifier.py` now delegates rejection-audit serialization and
  admission-state update shaping to `trackone_core.admission`, while native
  framed admission remains owned by the Rust ingest/gateway boundary.
- Publication-channel status reduction and manifest channel enablement override
  shaping now live behind `trackone_core.verification`, including shared
  OTS/TSA/peer/SCITT channel-name vocabulary.
- README surface labels and supported root workflow notes now match the current
  package/script split and the `justfile` implementation of `bench-rust`.
- The published `trackone-canonical-cbor-v1` vector manifest now names its CDDL profile, manifest schema, deterministic JSON-to-CBOR profile, and Merkle policy so external verifiers do not need to recover those rules from implementation comments.
- `commitment-artifacts-v1.cddl` now distinguishes the published JSON-projection fact leaf shape from lower-level Rust positional fact arrays, documents the deterministic JSON-to-CBOR and Merkle policies, and aligns `sample-type` with the current appended `SampleType` vocabulary.

## [0.1.0-alpha.16] - 2026-04-24

### Changed
- Gateway scripts that need native authority (`canonical_cbor.py`, `merkle_batcher.py`, and `verify_cli.py`) now import the stable `trackone_core.ledger`, `trackone_core.merkle`, and `trackone_core.ots` surfaces directly instead of reaching into `trackone_core._native`.
- The native gateway extension now exports a real `trackone_core.sensorthings` boundary for deterministic SensorThings entity IDs and observation projection, and the shared Python `trackone_core.sensorthings` module now delegates those deterministic steps to Rust instead of reimplementing them locally.
- `trackone-ingest` and `trackone-pod-fw` now default to their `no_std`-friendly surfaces; host-side replay/admission and pod test workflows opt into `std` explicitly through crate features and root `just` recipes.

## [0.1.0-alpha.15] - 2026-04-18

### Changed
- The supported framed-ingest path now treats native `trackone_core.crypto` admission as authoritative through replay-window decisions and canonical fact shaping, instead of leaving those steps to Python runtime authority after decrypt.
- `frame_verifier.py` remains the supported CLI/workflow entrypoint, but its normal admission path now delegates framed decrypt, duplicate/out-of-window rejection, and accepted-fact construction to the native gateway seam while Python retains file I/O, audit logging, schema routing, and device-table persistence.
- Roadmap and Internet-Draft-facing docs now describe the current execution boundary more explicitly: Python is still the workflow executor, while Rust owns selected authoritative hot-path operations including replay admission for the supported framed-ingest path.
- Verification-manifest disclosure metadata and the `publicly_recomputable` claim are now assembled from shared `trackone_core.release` helpers, so verifier output, pipeline manifest emission, and evidence-export rewrites use the same release-contract policy surface.
- `verify_cli.py` summary construction, check bookkeeping, manifest status updates, and channel result shaping now flow through shared `trackone_core.verification` helpers, so the verifier JSON/report contract and the local integrity gate use one report vocabulary instead of duplicating those rules inside the CLI.
- SensorThings projection mapping, provisioning-backed sensor identity resolution, and read-only bundle assembly now live in shared `trackone_core.sensorthings` helpers, while `sensorthings_projection.py` is reduced to schema validation, file loading, and CLI orchestration.
- The Python package surface was hardened for native-optional and wheel-test workflows: `trackone_core` now exports shared `sensorthings` and `verification` helpers directly, shim modules report missing native-extension failures more clearly, and wheel/import CI coverage was expanded across supported Python versions.

## [0.1.0-alpha.14] - 2026-04-13

### Changed
- Authoritative fact and day-artifact CBOR generation now go through native `trackone_core.ledger` helpers in normal runs, and commitment-capable workflows fail closed if the native ledger surface is unavailable or errors.
- Native Merkle recomputation is now required for normal gateway batching and verifier recompute paths; Python Merkle fallback is no longer used as runtime authority.
- Python CBOR and Merkle implementations remain in-tree only as explicit reference/parity fixtures, so corpus parity proves the Rust commitment path instead of substituting for it.
- `jsonschema` is no longer a mandatory base runtime dependency. Gateway and verifier runtime flows now skip schema validation explicitly when the library is unavailable, while validation-oriented tooling continues to require it and fails clearly when absent.

## [0.1.0-alpha.13] - 2026-04-03

### Added
- Native framed-ingest validation and AEAD decryption through `trackone_core.crypto`, so the gateway verifier no longer depends on direct PyNaCl calls for the authoritative ingest path.

### Changed
- `frame_verifier.py` now performs stricter framed-input validation, enforces nonce/material checks through the native helper, and supports a side-effect-free `--dry-run` mode for replay/audit workflows.
- The shared core vocabulary now treats imported pod identity metadata as `identity_input` rather than a TrackOne-owned provisioning/control-plane surface, and the dead `PolicyUpdate` type was removed.

## [0.1.0-alpha.12] - 2026-03-30

### Added
- Supported root workflow commands for the current local/demo and verification path.
- Benchmark entrypoints and documentation for corpus-backed speed/reliability checks against the published canonical CBOR commitment vectors.
- Minimal operator-facing docs for the supported local flow and benchmark flow.

### Changed
- The root task surface, README, and roadmap now point to one supported happy path for local demo and verification runs.
- Packaging and local bring-up ergonomics were tightened, so the current evidence/verification spine is easier to install, run, and verify without changing its contract.
- Rust/Python parity and reliability checks are easier to run against the published canonical CBOR corpus.
- Crate-level hardening in the existing workspace was limited to parity, diagnostics, seam cleanup, and packaging alignment; no new crate boundaries or protocol surfaces were introduced.

### Fixed
- Root-workflow friction and documentation drift between task runner, README, and release expectations.
- Packaging and verification-path issues that made the supported local flow harder to run repeatably.
- Benchmark/parity harness issues that interfered with repeatable corpus-backed measurements.

## [0.1.0-alpha.11] - 2026-03-19

### Added
- `toolset/unified/schemas/verify_manifest.schema.json` as the verifier-facing day-bundle contract for `day/<date>.verify.json`.
- `scripts/gateway/check_verify_manifest.py` as a fail-fast assertion surface for the demo/CI path.
- `scripts/dev/gen_commitment_vectors.py` plus the published corpus under `toolset/vectors/trackone-canonical-cbor-v1/`.
- Corpus-backed Python and Rust parity tests for the published canonical CBOR commitment vectors.
- `ADR-046` to record the sealed trust-root boundary, the current primitive-vs-orchestration split, and the explicit decision to defer a dedicated `trackone-seal` crate.
- TrackOne SCITT statement payload contracts and examples:
  - `toolset/unified/schemas/scitt_verify_manifest_statement.schema.json`
  - `toolset/unified/schemas/scitt_evidence_bundle_statement.schema.json`
  - `toolset/unified/cddl/scitt-statements-v1.cddl`
  - `toolset/unified/examples/scitt_verify_manifest_statement.json`
  - `toolset/unified/examples/scitt_evidence_bundle_statement.json`
  - `docs/scitt-trackone-statement-profile.md`

### Changed

- The alpha.11 verification-manifest / input-integrity / export / vector paths now use native `trackone_core.ledger` helpers for SHA-256 hex generation and `hex64` normalization, instead of scattered Python regex and `.hexdigest()` assumptions.
- The demo pipeline now treats manifest-backed local verification as mandatory: `run_pipeline_demo.py` fails on local integrity-gate failures, while `warn` mode still tolerates incomplete external anchoring channels.
- `frame_verifier.py` now fails closed on fact-schema violations instead of warning and writing the invalid fact anyway.
- `frame_verifier.py` and `provisioning_records.py` now require detached SHA-256 sidecars for `device_table.json` and `provisioning/authoritative-input.json`, and `pod_sim.py` refreshes those sidecars whenever it writes the trust-root inputs.
- `verify_cli.py` now consumes the verifier-facing manifest, reports manifest presence or absence explicitly in JSON output, and exposes `verification_manifest_validation` plus `batch_metadata_validation` as distinct executed/skipped checks.
- `tox -e pipeline` now fails if the verifier-facing manifest is missing, schema-invalid, or not consumed by `verify_cli`.
- Evidence export now preserves the verifier-facing manifest name, reruns a fresh `verify_cli` pass before copying any artifacts, and refuses to publish bundles whose current pipeline state no longer passes the local verification gate.
- Preferred-width CBOR float behavior is now explicitly gated in Python and Rust, including non-finite float rejection.
- Day chaining lookup in `merkle_batcher.py` now honors the requested `site_id` instead of linking to the most recent prior day record globally, and the integration tests now cover cross-site ignore behavior plus same-site fixture requirements.

## [0.1.0-alpha.10] - 2026-03-13

### Added
- `toolset/unified/schemas/provisioning_input.schema.json` as the authoritative deployment/provisioning input contract for the demo and projection path.
- `toolset/unified/schemas/pipeline_manifest.schema.json` as the locked machine-readable contract for emitted pipeline manifests.
- `toolset/unified/schemas/sensorthings_projection.schema.json` as the locked read-only SensorThings projection artifact contract.
- `scripts/evidence/export_release.py` to export a curated day-scoped evidence bundle and optionally commit/tag/bundle the result in a dedicated evidence repo.
- `docs/evidence-bundle-roundtrip.md` documenting a real signed Git-bundle export/import verification round-trip, including detached verifier output.
- Shared alpha.10 release constants in Rust/Python for `commitment_profile_id` and disclosure-class labels so the manifest/verifier contract is single-sourced across the native boundary.

### Changed
- The demo pipeline now separates runtime replay/key state from authoritative deployment/provisioning identity:
  - `device_table.json` remains runtime state only;
  - `provisioning/authoritative-input.json` carries deployment and provisioning metadata;
  - `provisioning_records.py` now consumes that authoritative input instead of reconstructing records from `device_table.json`.
- `run_pipeline_demo.py` now emits artifact digests for the locked manifest contract, and `verify_cli.py` validates `day/<date>.pipeline-manifest.json` when present.
- The demo pipeline manifest is now publication-safe for evidence export: embedded verifier summaries no longer carry host-local artifact paths, and `clean_outputs()` removes `audit/` as workspace residue alongside other regenerated output directories.
- The demo workspace now treats `day/` as the complete day evidence set / anchoring set:
  - OTS metadata now lives under `day/` instead of a separate top-level `proofs/` directory;
  - the sample manifest records `day_ots_meta`;
  - detached bundle verification now runs against that joined layout.
- `sensorthings_projection.py` now validates its emitted bundle against the checked-in projection schema before writing it.

## [0.1.0-alpha.9] - 2026-03-12

### Added
- A first CDDL contract for the CBOR-authoritative commitment family in `toolset/unified/cddl/commitment-artifacts-v1.cddl`, covering canonical `EnvFact`, `Fact`, `BlockHeaderV1`, and `DayRecordV1`.
- A parser-backed Rust conformance gate in `trackone-ledger` that parses the checked-in CDDL and asserts the expected top-level rule set.

### Changed
- The Rust workspace minimum version is now `1.88` so the CDDL parser-backed gate can rely on the published `cddl` crate.
- Unified JSON Schema contracts were refactored around shared definitions and cross-file `$ref` reuse, with `common.schema.json` introduced as the shared schema registry surface.
- Runtime schema validation in the Python gateway now goes through a centralized registry-aware loader/validator, so cross-file `$ref` resolution works consistently across fact, device table, day, OTS, and projection artifacts.
- Integration coverage now validates every checked-in schema document against its metaschema and includes schema-only coverage for `peer_attest`.

## [0.1.0-alpha.8] - 2026-03-11

### Changed
- Canonical fact convergence for the Python gateway:
  - `scripts/gateway/frame_verifier.py` now emits the canonical top-level fact shape without the transitional `device_id`, `timestamp`, and `nonce` compatibility keys.
  - `toolset/unified/schemas/fact.schema.json` now defines only the canonical fact contract.
  - `scripts/gateway/sensorthings_projection.py` now requires canonical fact identifiers/timestamps and reports `read_only_canonical_fact_json` output mode.
- Hard-break provisioning/demo alignment:
  - `scripts/pod_sim/pod_sim.py` now seeds current-schema `deployment` and `provisioning` blocks into demo device tables, so the demo pipeline remains runnable under the strict provisioning contract.
  - `scripts/gateway/provisioning_records.py` now validates authoritative provisioning fields strictly, including hex formatting, instead of fabricating missing identity or deployment data.
  - `scripts/gateway/verify_cli.py` now rejects legacy `day/*.bin` artifacts with an explicit migration message.
- Rust workspace/tooling hardening:
  - the workspace baseline now targets Rust edition `2024`;
  - `trackone-pod-fw` local/test code was adjusted for Rust 2024 reserved-keyword compatibility;
  - bundled canonical fact vectors and schema-oriented tests now follow the canonical fact contract.

## [0.1.0-alpha.7] - 2026-03-07

### Added
- Canonical fact migration groundwork:
  - `frame_verifier.py` now emits canonical top-level fact fields (`pod_id`, `fc`, `ingest_time`, `pod_time`, `kind`) alongside legacy compatibility fields during the transition.
  - `scripts/gateway/sensorthings_projection.py` accepts canonical fact shapes directly while still tolerating older fact JSON on input.
- Provisioning-backed SensorThings projection inputs:
  - Added `scripts/gateway/provisioning_records.py` and `toolset/unified/schemas/provisioning_records.schema.json`.
  - `run_pipeline_demo.py` now emits `provisioning/records.json` and feeds it into SensorThings projection.

### Changed
- SensorThings projection hardening:
  - missing deployment/provisioning-backed sensor identity is now an explicit projection failure instead of silently generating synthetic Sensor IDs;
  - CLI projection now exits non-zero on unresolved sensor identity;
  - provisioning/deployment metadata is schema-validated before projection starts.
- Disclosure-aware verification behavior:
  - fact-level recomputation now only runs for disclosure class `A`;
  - disclosure classes `B` and `C` explicitly skip fact-level recomputation and report that the bundle is not publicly recomputable;
  - verifier summaries now expose `checks_executed` / `checks_skipped` for machine-readable partial-disclosure reporting.
- The experimental Python SensorThings native bridge surface was removed:
  - `trackone_core.sensorthings` shim is no longer exported;
  - `crates/trackone-gateway` no longer registers a SensorThings PyO3 submodule.
- Workspace crate versions are aligned to `0.1.0-alpha.7` for the alpha.7 release cut.

### Notes
- `alpha.7` is a hardening release, not full closure of the current migration plan.
- Canonical fact convergence remains in progress:
  - the live Python gateway still emits a transitional fact JSON shape with legacy fields, rather than a pure `trackone-core::Fact` / `EnvFact` contract end-to-end.
- Provisioning-backed sensor identity is improved but not fully formalized:
  - projection now requires provisioning records, but those records are still derived from the current device-table/deployment metadata path rather than a fully separate validated provisioning source of truth.
- ADR-041/043 Phase B disclosure manifests are only partially shipped in `alpha.7`:
  - pipeline/verifier outputs now carry `disclosure_class`, `commitment_profile_id`, and executed/skipped-check metadata;
  - standalone bundle packaging and a locked artifact-digest/verification-bundle contract remain for a later phase.
- Environment hardening is partial:
  - `verify_cli.py` avoids one direct `PyNaCl` import trap through lazy peer-verification loading, but the demo/frame-ingest path still depends on `PyNaCl` being installed.

## [0.1.0-alpha.6] - 2026-03-01

### Added
- `trackone-pod-fw` now includes a hardware watchdog slice for unattended pod recovery: quorum-based liveness tracking, a local reset-counter persistence hook, and mock watchdog support for host-side tests.

### Changed
- Workspace crate versions are aligned to `0.1.0-alpha.6` for the alpha.6 release cut.

## [0.1.0-alpha.5] - 2026-02-27

### Added
- Native `trackone_core.ots` boundary helpers in `trackone-gateway`: `verify_ots_proof`, `validate_meta_sidecar`, `OtsStatus`, and `OtsVerifyResult`.
- Rust unit coverage for OTS placeholder, stationary stub, real proof, and metadata sidecar validation paths.
- `scripts/gateway/frame_verifier.py` now emits structured rejection evidence to `audit/rejections-<day>.ndjson` for parse, replay, and decrypt rejects.
- Python test coverage for rejection audit logging, append behavior, and Merkle/audit separation.

### Changed
- `scripts/gateway/verify_cli.py` now prefers `trackone_core.ots` for OTS proof and sidecar validation when the native extension is available, while preserving the Python fallback helpers.
- OTS verification now uses a bounded default timeout and a shared hash helper for the native boundary.
- `scripts/gateway/merkle_batcher.py` now documents that sibling `audit/` evidence is not part of ledger inputs and must not affect Merkle roots.
- Workspace crate versions are aligned to `0.1.0-alpha.5`, and ADR-038 now lists the OTS boundary checks as protocol-critical operations.

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
  - Added identity-input module for device identity and chain-of-trust input
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
  `deploy/docker/calendar/` and used by the `ots-cal` and weekly ratchet workflows.
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
- **LaTeX manuscript structure**: Initial manuscript entrypoint with section includes

## [0.0.0] - 2025-09-15

### Added

- Initial repository structure
- Project planning documents
- Milestone requirements specification
