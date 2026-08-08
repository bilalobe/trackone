# Changelog

All notable changes to the `trackone-evidence` application package will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.5] - 2026-08-08

### Added

- Add readable manifest envelope v3 with exact-byte record packs,
  `compact`, bounded deterministic gzip carriers, and archive verification.
  Manifest v3 is active for the canonical Class A vector and compact output;
  manifest v2 remains readable compatibility input.

### Changed

- Align the application with the Rust-only workspace product boundary after
  removal of the unpublished `trackone-python` binding leaf.
- Remove the legacy v1 verification/export implementation and expose only the
  forward-only v2 `verify` and `compact` commands, with no aliases.
- Make `--json` compact and add explicit `--pretty` formatting.
- Add `--tsa-signer-cert-sha256` and require RFC 5816 signer-certificate
  binding for every present RFC 3161 timestamp response.
- Narrow manifest v3 to discovery-critical artifacts and producer
  `present`/`pending` claims. Narrow verification-result v2 to scope, checks,
  channel outcomes, policy identity, and overall outcome; evaluable failures
  now produce `overall=failure` before the CLI exits nonzero.
- Bound every artifact read, validate gzip in one pass, reject concatenated or
  trailing members, and retain manifest v2 only as read-only input.

## [0.1.0-beta.4] - 2026-07-18

### Added
- Added corpus-driven `verify-v2` CLI replay for corrected Class-A epoch and
  successor bundles plus the archived segment-7/zero-predecessor failure
  bundle.

### Changed
- Moved the package under `apps/`, replaced its mixed gateway dependency with
  a direct `trackone-ots` dependency, and split the library into verification,
  export, policy, manifest, bundle, and Git modules while preserving public
  crate-root entry points.
- V2 test artifact construction now uses the ledger-owned validated epoch and
  successor constructors, preserving fail-fast chain validation before
  Class-A recomputation or proof-channel work.

## [0.1.0-beta.2] - 2026-07-11

### Added
- Added the `verify-v2` CLI command and native v2 bundle verifier. It decodes
  authoritative segment CBOR through `trackone-ledger`, compares manifest
  identity claims, validates disclosed predecessor-artifact linkage, and for
  Class A validates exact canonical records against authoritative batch leaves
  and the segment root. This command is a draft-08 verification preview rather
  than a complete producer or timestamp-channel conformance claim.

## [0.1.0-beta.1] - 2026-05-16

### Notes
- No crate-local API changes landed in this release; `trackone-evidence`
  remains aligned with the workspace `0.1.0-beta.1` release line.

## [0.1.0-alpha.19] - 2026-05-16

### Added
- Introduced `trackone-evidence` as the Rust-native verifier/export runner for
  TrackOne evidence bundles, with `verify` and `export` CLI subcommands.
- Added manifest, artifact, fact-level recompute, batch metadata, and OTS
  verification checks backed by `trackone-ledger` canonical CBOR/Merkle helpers
  and `trackone-gateway` OTS helpers.
- Added evidence export support for release-day artifacts, optional frame
  inclusion, fresh verification, optional git commit/tag creation, and optional
  git bundle emission.
- Added crate-local Rust tests covering the native evidence contract.
