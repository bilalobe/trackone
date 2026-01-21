# Changelog

All notable changes to `trackone-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.2] - 2026-01-21

### Added
- **Provisioning module** (`src/provisioning.rs`): `ProvisioningRecord` and `PolicyUpdate` for device identity and chain of trust (ADR-019, ADR-034)
- **Deterministic CBOR commitments** (`src/cbor.rs`): TrackOne CBOR profile for stable cryptographic commitments
  - Array-based positional encoding with embedded schema version (v1)
  - Integer discriminants for `FactPayload` variants
  - Deterministic float policy (always encode `f32` as CBOR float32)
- **Environmental sensing types**: `EnvFact`, `SampleType`, `SensorCapability`, `FactKind` aligned with OGC SensorThings terms (phenomenonTime/resultTime)
- **Serialization benchmarks**: size comparison tests for Postcard vs CBOR vs JSON (`tests/serialization_benchmarks.rs`)
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
- Added reproducible size comparisons (see `tests/serialization_benchmarks.rs`). Example results on this release:
  - `ProvisioningRecord`: 177 B (Postcard) vs 185 B (CBOR) vs 633 B (JSON)
  - `PolicyUpdate`: 85 B (Postcard) vs 88 B (CBOR) vs 378 B (JSON)
  - `EnvFact` (embedded in `Fact`): 55 B (Postcard) vs 60 B (CBOR) vs 296 B (JSON)


## [0.1.0-alpha.1] - 2025-01-20

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
