# Changelog

All notable changes to `trackone-gateway` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.15] - 2026-04-18

### Added
- Native `ReplayWindowState` plus `trackone_core.crypto.admit_framed_fact(...)` for the supported framed-ingest path, so Python callers can hand framed input, per-device material, and replay state to one native admission boundary.

### Changed
- The native crypto surface now owns duplicate/out-of-window replay decisions and accepted-fact construction for the supported framed-ingest path, extending the earlier decrypt/material-validation boundary instead of returning only a loose decoded payload to Python.
- Python-facing framed-input extraction and replay-state handling were tightened around the new admission helper, including stricter type rejection on the boundary and clearer separation between decrypt and replay rejection causes.

## [0.1.0-alpha.14] - 2026-04-13

### Changed
- Native `trackone_core.ledger` and `trackone_core.merkle` helpers are now required for commitment-critical normal runs, so authoritative fact/day CBOR generation and Merkle recomputation fail closed instead of falling back to Python runtime authority.
- Python CBOR and Merkle implementations are retained only as explicit reference/parity helpers; the normal gateway and verifier paths now treat the native extension as the authoritative commitment boundary.

## [0.1.0-alpha.13] - 2026-04-03

### Added
- Native `trackone_core.crypto.validate_and_decrypt_framed(...)` helper for framed-ingest material validation, nonce-policy enforcement, XChaCha20-Poly1305 decryption, and TLV payload decoding.

### Changed
- The Python gateway verifier now relies on the native crypto surface for authoritative framed decrypt/validation instead of direct PyNaCl calls.

## [0.1.0-alpha.12] - 2026-03-30

### Notes
- No new Rust-side gateway API surface was added in this release; the crate remains aligned with the workspace `0.1.0-alpha.12` release line while the supported local/demo and verification workflows were tightened around the existing boundary.

## [0.1.0-alpha.11] - 2026-03-19

### Added
- Exposed native `sha256_hex` and `normalize_hex64` helpers through the `trackone_core.ledger` PyO3 surface so the alpha.11 manifest/integrity paths can share one digest and `hex64` contract.

## [0.1.0-alpha.10] - 2026-03-13

### Added
- Exported alpha.10 release-contract constants from the native extension root so Python callers can share the canonical `commitment_profile_id` and disclosure-class labels with the Rust workspace.

## [0.1.0-alpha.9] - 2026-03-12

### Notes
- No new Rust-side gateway API surface was added in this release; the crate stays aligned with the workspace `0.1.0-alpha.9` release line while the operational hardening work remained concentrated in the Python gateway/demo path.

## [0.1.0-alpha.8] - 2026-03-11

### Notes
- No new Rust-side gateway API surface was added in this release; the crate stays aligned with the workspace `0.1.0-alpha.8` release line while the operational hardening work remained concentrated in the Python gateway/demo path.

## [0.1.0-alpha.7] - 2026-03-07

### Added
- Feature-gated `sensorthings` domain module for deterministic SensorThings projection helpers:
  - entity ID derivation;
  - RFC3339 validation and UTC formatting;
  - canonical observation projection types and mapping;
  - adapter helpers from `trackone-core::Fact` / `EnvFact`.
- Provisioning-aware SensorThings adapter inputs:
  - deployment and provisioning sensor keys can be passed explicitly;
  - stable `prov-...` sensor keys can be derived from provisioning identity when needed.

### Changed
- SensorThings adapter hardening:
  - missing provisioning/deployment-backed sensor identity now returns an explicit adapter error instead of falling back to `sensor-default` or channel placeholders.
- Removed the experimental `trackone_core.sensorthings` Python bridge surface; Python callers should use the projection script/domain directly.

### Notes
- The Rust `sensorthings` module is a framework/helper boundary for projection logic, validation, and IDs.
- It is not yet the authoritative live gateway ingress path; the Python gateway still emits transitional fact JSON on the operational pipeline side.

## [0.1.0-alpha.6] - 2026-03-01

### Notes
- No gateway-specific changes in this release; the crate version is aligned with the workspace `0.1.0-alpha.6` release.

## [0.1.0-alpha.5] - 2026-02-27

### Added
- `ots` submodule now exposes `hash_for_ots(...)`, `verify_ots_proof(...)`, `validate_meta_sidecar(...)`, and the `OtsStatus` / `OtsVerifyResult` result types for native OTS boundary checks.
- Rust unit tests now cover placeholder proofs, stationary stubs, real proofs, and OTS metadata validation edge cases.

### Changed
- Added direct `sha2`, `serde_json`, and `trackone-constants` dependencies so OTS validation logic can hash artifacts, parse sidecars natively, and share the default verify timeout constant.

## [0.1.0-alpha.4] - 2026-02-26

### Added
- `ledger` submodule exposes `canonicalize_json_bytes`, `canonicalize_json_to_cbor_bytes`, `build_day_v1_single_batch`, and `build_day_v1_single_batch_cbor`, giving Python callers deterministic JSON and CBOR helpers backed by the workspace `trackone-ledger` helpers.

### Changed
- Ledger helpers now delegate to the workspace `trackone-ledger` canonicalization modules when producing deterministic CBOR commitments for the Python gateway surface.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- High-level Python gateway API:
  - `Gateway` and `GatewayBatch` exposed from the `trackone_core` extension module
  - `PyRadio` adapter for Python-implemented `send_frame`/`receive_frame`
- Merkle helpers:
  - ADR-003 Merkle root policy (SHA-256, hash-sorted leaves), implemented in `trackone-ledger`
  - `trackone_core.merkle.merkle_root_bytes` and `trackone_core.merkle.merkle_root_hex`
  - `trackone_core.merkle.merkle_root_hex_and_leaf_hashes` (root + leaf hashes, Python pipeline parity)
- Ledger helpers:
  - `trackone_core.ledger.canonicalize_json_bytes` (ADR-003 canonical JSON)
  - `trackone_core.ledger.build_day_v1_single_batch` (canonical block header + `day.bin` bytes)

### Changed
- `__version__` now reports the crate version (`CARGO_PKG_VERSION`)
- `trackone_core.crypto.version()` now matches the crate version (was a placeholder string)
- Merkle policy logic moved out of `trackone-gateway` and is now single-sourced in `trackone-ledger`
- Removed the legacy `merkle_policy` module (now provided by `trackone-ledger`)

## [0.1.0-alpha.2] - 2026-01-22

### Changed
- Minor version alignment with `trackone-core` v0.1.0-alpha.2
- Updated dependency on `trackone-core` to benefit from new provisioning types and CBOR encoding

### Notes
- No API changes in this release
- Gateway functionality remains compatible with alpha.1

## [0.1.0-alpha.1] - 2025-01-20

### Added
- Initial PyO3-based Python extension for gateway integration
- Core gateway bindings for TrackOne protocol
