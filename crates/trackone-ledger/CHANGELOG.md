# Changelog

All notable changes to `trackone-ledger` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Deterministic CBOR commitment helpers in `src/c_cbor.rs`:
  - `canonical_cbor_bytes`
  - `canonicalize_json_bytes_to_cbor`
  - `canonicalize_serialize_to_cbor`
- CBOR serialization support on ledger records:
  - `BlockHeaderV1::canonical_cbor_bytes`
  - `DayRecordV1::canonical_cbor_bytes`
- Unit-test coverage for deterministic CBOR behavior, including map key ordering and integer encoding.

### Changed
- Deterministic map-key ordering for JSON object keys now follows RFC 8949 Section 4.2.1 semantics for text keys:
  - sort by UTF-8 encoded key length, then lexicographic UTF-8 bytes.

## [0.1.0-alpha.3] - 2026-02-07

### Added
- Initial crate with:
  - Canonical JSON encoding helpers (ADR-003)
  - ADR-003 Merkle policy implementation (root + leaf hashes)
  - `BlockHeaderV1` / `DayRecordV1` helpers and canonical JSON byte encoding
