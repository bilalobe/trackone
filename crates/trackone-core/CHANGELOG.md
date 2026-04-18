# Changelog

All notable changes to `trackone-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.15] - 2026-04-18

### Added
- Shared Python helper modules for release-contract/reporting and projection policy:
  - `trackone_core.release` now includes disclosure-label, public-recompute, and manifest-bundle helpers.
  - `trackone_core.verification` now owns verifier-summary/check bookkeeping helpers used by the CLI and local verification gate.
  - `trackone_core.sensorthings` now owns deterministic SensorThings projection, provisioning-backed sensor identity resolution, and bundle assembly.

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.15` to match the workspace release.
- The `trackone_core` package root now exports the shared `sensorthings` and `verification` helper surfaces directly.
- Native shim modules (`crypto`, `ledger`, `merkle`, `ots`, `radio`) now handle missing `_native` imports more explicitly and more safely for wheel-only/native-optional workflows.

## [0.1.0-alpha.14] - 2026-04-13

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.14` to match the workspace release.

## [0.1.0-alpha.13] - 2026-04-03

### Changed
- Renamed the shared lifecycle-adjacent module from `provisioning` to `identity_input` so the crate surface reads as imported identity/admission context at the admitted-telemetry boundary, not as a TrackOne-owned lifecycle subsystem.
- Removed the dead `PolicyUpdate` type and its canonical CBOR encoding so `trackone-core` no longer advertises a latent control-plane policy contract.

## [0.1.0-alpha.12] - 2026-03-30

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.12` to match the workspace release.

## [0.1.0-alpha.11] - 2026-03-19

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.11` to match the workspace release.

## [0.1.0-alpha.10] - 2026-03-13

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.10` to match the workspace release.
- Re-exported the shared alpha.10 release-contract constants from `trackone-constants`, including the canonical `commitment_profile_id` and disclosure-class labels used by the manifest/verifier surface.

## [0.1.0-alpha.9] - 2026-03-12

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.9` to match the workspace release.

## [0.1.0-alpha.8] - 2026-03-11

### Notes
- No crate-local API changes in this release; the crate remains aligned with the workspace `0.1.0-alpha.8` release line.

## [0.1.0-alpha.7] - 2026-03-07

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.7` to match the workspace release.

## [0.1.0-alpha.6] - 2026-03-01

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.6` to match the workspace release.
- Re-exported `DEFAULT_WATCHDOG_MS` from `trackone-constants` so firmware consumers can use the shared watchdog timeout policy through `trackone-core`.

## [0.1.0-alpha.5] - 2026-02-27

### Changed
- `trackone-core::VERSION` now reports `0.1.0-alpha.5` to match the workspace release.

## [0.1.0-alpha.4] - 2026-02-26

### Notes
- No crate-local API changes in this cycle; current alpha.4 work is concentrated in `trackone-ledger` and `trackone-gateway`.

### Changed
- PyO3 packaging now emits the native extension as `trackone_core._native` while the crate root provides a shim that catches missing `_native` imports and keeps `Gateway`, `GatewayBatch`, `PyRadio`, and `__version__` callable from Python.
- Added tests that force `_native` import failure so the crate remains usable in environments where the compiled extension is unavailable.

## [0.1.0-alpha.3] - 2026-02-07

### Changed
- Re-exported AEAD sizing constants from `trackone-constants`: `AEAD_NONCE_LEN`, `AEAD_TAG_LEN`.
- Wired framing/types to use the shared constants (reduces magic numbers and keeps crates aligned).

## [0.1.0-alpha.2] - 2026-01-21

### Added
- **Identity-input module** (`src/identity_input.rs`): `ProvisioningRecord` for device identity and chain-of-trust input (ADR-019, ADR-034)
- **Deterministic CBOR commitments** (`src/cbor.rs`): TrackOne CBOR profile for stable cryptographic commitments
  - Array-based positional encoding with embedded schema version (v1)
  - Integer discriminants for `FactPayload` variants
  - Deterministic float policy (always encode `f32` as CBOR float32)
- **Environmental sensing types**: `EnvFact`, `SampleType`, `SensorCapability`, `FactKind` aligned with OGC SensorThings terms (phenomenonTime/resultTime)
- **Production guardrail**: compile-time refusal when `production` and `dummy-aead` are enabled together
- **Re-exports**: common core types re-exported from crate root for ergonomic use in pod-fw and gateway

### Changed
- **BREAKING**: `PodId` expanded from `u32` to `[u8; 8]` for future extensibility
  - `From<u32>` remains available (stores the `u32` in the last 4 bytes, big-endian)
  - `From<[u8; 8]>` provided for direct construction
- **BREAKING**: `FactPayload` replaced earlier sensor-specific variants with `Env(EnvFact)` and a bounded `Custom(Vec<u8, 64>)`
- **BREAKING**: `Fact` now carries explicit time semantics: `ingest_time: i64` and `pod_time: Option<i64>`, plus `kind: FactKind`
- **CBOR commitments**: explicitly documented as a **TrackOne deterministic profile** (inspired by RFC 8949, but not a claim of strict RFC 8949 canonical-CBOR compliance)

### Fixed
- Updated tests to match `PodId([u8; 8])` representation and roundtrip/size assertions for the new Fact schema

### Security
- Enforced the `production` + `dummy-aead` incompatibility at compile time (prevents unsafe test crypto from shipping)

### Documentation
- Documented the CBOR profile, schema versioning, and the “field order is part of the commitment contract” rule

### Performance
- Added reproducible size comparisons between Postcard, TrackOne CBOR, and JSON.
  - Example results for `0.1.0-alpha.2` \(measured on Linux, Rust \`1.xx\`, \`--release\`, features: \`...\`\):
    - `ProvisioningRecord`: 177 B \(Postcard\) vs 185 B \(CBOR\) vs 633 B \(JSON\)
    - `EnvFact` \(embedded in `Fact`\): 55 B \(Postcard\) vs 60 B \(CBOR\) vs 296 B \(JSON\)

## [0.1.0-alpha.1] - 2025-12-20

### Added
- Initial alpha release
- Core types: `PodId`, `FrameCounter`, `Fact`, `FactPayload`, `EncryptedFrame`
- Cryptographic abstractions: `SymmetricKey`, `Nonce`, AEAD trait
- Frame construction and encryption helpers
- Merkle tree support for gateway (with `gateway` feature)
- Dummy AEAD implementation for testing (with `dummy-aead` feature)
- Postcard serialization for wire format
- `no_std` support with heapless collections

### Notes
- This was the first tagged release, establishing baseline functionality
