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

`- **ADR‑007: OTS verification in CI and Bitcoin headers policy**
  Status: Accepted (M#4)
  Summary: Trustless OTS verification in CI using Bitcoin Core in headers-only/pruned mode with cached datadir; parse
  required heights from `.ots` artifacts, wait for headers to catch up, then run `ots verify`. Skip non-blocking when
  headers are unavailable within timeout.

## Implementation Status

| ADR     | M#0        | M#1                          | M#2                     |
|---------|------------|------------------------------|-------------------------|
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
2. Number sequentially (ADR-004, ADR-005, etc.)
3. Submit as PR with "ADR: " prefix
4. Mark as "Proposed" until discussed and accepted
5. Update this README index when accepted
