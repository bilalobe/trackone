# Architecture Decision Records (ADRs)

This directory contains the key design decisions for Track1 (secure telemetry + verifiable ledger).
Each ADR captures context, the decision, consequences, and alternatives.

## Index (Project)

### Core Cryptography & Framing

- **ADR‑001: Cryptographic Primitives and Framing**
  Status: Accepted (M#0)
  Summary: Establishes modern, efficient primitives for provisioning and AEAD telemetry:

  - X25519 + HKDF for key derivation
  - XChaCha20‑Poly1305 for AEAD (M#2 implementation)
  - Ed25519 for identity/config/firmware signatures
  - SHA‑256 for Merkle trees and hashing

- **ADR‑002: Telemetry Framing, Nonce/Replay Policy, and Device Table**
  Status: Accepted (M#1 stub)
  Summary: Defines compact frame layout and gateway security policies:

  - Frame header: dev_id(u16), msg_type(u8), fc(u32), flags(u8)
  - 24‑byte XChaCha nonce construction: salt(8)||fc(8)||rand(8)
  - Gateway replay window with configurable size (default: 64)
  - Device table for per-device state tracking (highest_fc_seen, last_seen)
  - M#1 implementation: stub decryption (base64 JSON), real AEAD in M#2

- **ADR‑003: Canonicalization, Merkle Policy, and Daily OpenTimestamps Anchoring**
  Status: Accepted (M#0, M#1)
  Summary: Ensures deterministic, verifiable data integrity:

  - Canonical JSON: sorted keys, UTF-8, no whitespace
  - Hash-sorted Merkle leaves for order independence
  - Day chaining via prev_day_root (32 zero bytes for genesis)
  - Daily OTS anchoring for public timestamp verification
  - Schema validation for facts, block headers, and day records

- **ADR‑004: Framed Ingest Stub for M#1 (Plaintext CT for Pipeline Bring‑up)**
  Status: Accepted (M#1)
  Summary: Documents the temporary plaintext-ciphertext stub used to bring up the end-to-end pipeline before real AEAD; replay window enforced; canonical facts emitted.

- **ADR‑005: PyNaCl Migration**
  Status: Accepted (M#3)
  Summary: Consolidate all cryptographic operations to PyNaCl (libsodium):

  - Removed `cryptography` dependency
  - Unified API for X25519, HKDF, ChaCha/XChaCha AEAD, Ed25519
  - Regenerated test vectors with PyNaCl bindings
  - Improved maintainability and performance

### Policy & Process

- **ADR‑006: Forward-only schema policy and deprecating `salt4`**
  Status: Accepted (M#2)
  Summary: Adopt a forward-only policy. Standardize on `salt8` for XChaCha (24‑byte nonce), drop `salt4` and migrations;
  the current milestone schema is the only valid runtime format. Older milestones are archived as references only.

- **ADR‑007: OTS verification in CI and Bitcoin headers policy**
  Status: Accepted (M#4)
  Summary: Trustless OTS verification in CI using Bitcoin Core in headers-only/pruned mode with cached datadir; parse
  required heights from `.ots` artifacts, wait for headers to catch up, then run `ots verify`. Skip non-blocking when
  headers are unavailable within timeout.

- **ADR‑008: Milestone M#4 Completion and OTS Verification Workflow**
  Status: Accepted (M#4)
  Summary: Records the production OTS anchoring/verification of a day blob, CLI verification modes, and Git LFS policy for `.ots` artifacts with associated metadata.

- **ADR‑009: Bandit findings remediation and decisions**
  Status: Accepted (M#4)
  Summary: Hardens subprocess usage and exception handling around `ots` calls; documents selective `# nosec` justifications and CI policy to reduce false positives while keeping security signal.

- **ADR‑010: Test suite refactor (structure and naming)**
  Status: Proposed (M#4→M#5)
  Summary: Decompose monolith tests, move fixtures closer to submodules, and adopt clearer naming (drop `_edge_cases`, `_boost`); improves focus and iteration speed.

- **ADR‑013: Python Version Support Policy (Last Three Minors)**
  Status: Proposed
  Summary: Always support the last three CPython minors in CI/tox (currently 3.12, 3.13, 3.14); drop the oldest from defaults when a new minor releases; keep a dedicated env for explicit checks.

- **ADR‑014: Stationary OpenTimestamps Calendar for Deterministic Anchoring**
  Status: Proposed (M#5)
  Summary: Introduce a self-hosted OTS calendar for CI/local determinism with configurable fallback to public pools; outlines deployment and verification flow.

- **ADR‑015: Parallel Anchoring with OpenTimestamps and RFC 3161 TSA**
  Status: Proposed (M#5)
  Summary: For each daily Merkle root, produce and store both an OTS proof and an RFC 3161 TSA response over the same digest; verify both in CI/CLI and treat dual success as strongest assurance while remaining backward-compatible with OTS-only.

- **ADR‑016: Changelog Policy and Automation with git-cliff**
  Status: Proposed (M#5)
  Summary: Adopt `git-cliff` with a project `cliff.toml` to generate and validate CHANGELOG sections from conventional commits; gate releases in CI and surface breaking/migration notes.

- **ADR‑017: Rust Core and PyO3 Integration Strategy (Latent Goal)**
  Status: Proposed (M#6)
  Summary: Introduce a Rust core crate with PyO3 bindings for canonicalization, hashing, Merkle, and eventually AEAD/signatures; ship wheels with `maturin`, keep Python API stable with fallbacks, and roll out in phases post‑0.1.0.

- **ADR‑018: Cryptographic randomness and nonce policy**
  Status: Accepted
  Summary: Standardize OS‑backed CSPRNG usage across Python and Rust; prohibit non‑CSPRNG APIs in crypto contexts; define AEAD nonce sizes and salt policy (16–32 bytes), provide `crypto_rng.py` helper, and require test fakes for deterministic tests.

### Platform Evolution

- **ADR‑017: Rust Core and PyO3 Integration Strategy (Latent Goal)**
  Status: Proposed (M#6)
  Summary: Introduce a Rust core crate with PyO3 bindings for canonicalization, hashing, Merkle, and eventually AEAD/signatures; ship wheels with `maturin`, keep Python API stable with fallbacks, and roll out in phases post‑0.1.0.

## Tooling & Performance

- **ADR‑011: Benchmarking Strategy for TrackOne**
  Status: Accepted (M#5)
  Summary: Introduces pytest-benchmark based micro/mid-level benchmarks for crypto and gateway primitives, optional CI artifacts, and conventions for running and comparing baselines.

## Data Storage & Analytics

- **ADR‑012: Parquet Export for Telemetry Facts (0.2.0+)**
  Status: Proposed
  Summary: Add optional Parquet exporter (columnar, partitioned by day/site) derived from canonical JSON; keeps JSON as source of truth for Merkle/OTS, improves analytical scans and storage efficiency.

## Implementation Status

| ADR     | M#0        | M#1                          | M#2                     |
| ------- | ---------- | ---------------------------- | ----------------------- |
| ADR-001 | Schema     | Stub                         | Real AEAD               |
| ADR-002 | -          | Stub decrypt + replay window | Key lookup + tag verify |
| ADR-003 | ✓ Complete | ✓ Complete                   | Persistent state        |

## Usage

- **ADRs guide implementation**: Do not change code that contradicts an "Accepted" ADR without opening a new ADR (
  Status: Proposed).
- **Cross-reference in code**: Use ADR IDs in docstrings and comments (e.g., "implements ADR‑002 nonce policy").
- **Review process**: Proposed → Discussed → Accepted → Implemented

## Recent Changes (M#1)

### ADR-002 Implementation

- ✓ Frame parser with header validation (dev_id, msg_type, fc, flags)
- ✓ Replay window enforcement (configurable, default: 64)
- ✓ Per-device state tracking (highest_fc_seen, seen_set)
- ✓ Stub decryption (base64-encoded JSON payload)
- ✓ Canonical fact emission

### Test Coverage

- ✓ Frame parsing (valid/invalid structure)
- ✓ Replay window (monotonic, duplicates, out-of-window)
- ✓ End-to-end pipeline (pod_sim → frame_verifier → verify_cli)

## Template (for new ADRs)

```markdown
# ADR-XYZ: Title

**Status**: Proposed | Accepted | Superseded
**Date**: YYYY-MM-DD

## Context

- Problem statement and constraints
- Why this decision is needed

## Decision

- The chosen approach and scope
- Key design elements

## Consequences

### Positive

- Benefits and advantages

### Negative

- Trade-offs and limitations
- Operational impact

## Alternatives Considered

- Brief notes on rejected options
- Why they were not chosen

## Testing & Migration

- How to validate the implementation
- Migration path if changing existing behavior
```

## Contributing

When proposing a new ADR:

1. Copy the template above
1. Number sequentially (ADR-004, ADR-005, etc.)
1. Mark as "Proposed" until discussed and accepted
1. Update this README index when accepted
