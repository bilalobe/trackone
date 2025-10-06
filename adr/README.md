# Architecture Decision Records (ADRs)

This directory contains the key design decisions for Track 1 (secure telemetry + verifiable ledger) and related platform
notes. Each ADR captures context, the decision, consequences, and alternatives.

## Index (Project)

- ADR‑001: Cryptographic Primitives and Framing — X25519 + HKDF + XChaCha20‑Poly1305  
  Status: Accepted  
  Summary: Establishes modern, efficient primitives for provisioning and AEAD telemetry, with Ed25519 for
  identity/config/firmware.

- ADR‑002: Telemetry Framing, Nonce/Replay Policy, and Device Table  
  Status: Accepted  
  Summary: Defines compact binary frame layout (dev_id, msg_type, fc, flags, AEAD), 24‑byte XChaCha nonce (
  salt8||fc8||rand8), and gateway replay window/state.

- ADR‑003: Canonicalization, Merkle Policy, and Daily OpenTimestamps Anchoring  
  Status: Accepted  
  Summary: Fixes canonical JSON bytes, hash‑sorted Merkle leaves, day chaining via prev_day_root, and daily OTS
  anchoring/verification.

## Usage

- ADRs guide implementation, tests, and reviews. Do not change code that contradicts an “Accepted” ADR without opening a
  new ADR (Status: Proposed).
- Cross‑reference ADR IDs in code comments and PR descriptions (e.g., “implements ADR‑002 nonce policy”).

## Template (for new ADRs)

# ADR-XYZ: Title

Status: Proposed | Accepted | Superseded Date: YYYY-MM-DD
Context

- Problem and constraints.

Decision

- The choice and scope.

Consequences

- Trade-offs, limitations, ops impact.

Alternatives Considered

- Brief notes on rejected options.

Testing & Migration

- How this is validated and rolled out.```

## Related platform notes

If you keep workstation or ops ADRs (e.g., security baselines), store them under `adr/platform/` and link from the
project README rather than mixing with Track1 ADRs.