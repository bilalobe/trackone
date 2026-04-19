# ADR-002: Telemetry Framing, Nonce/Replay Policy, and Device Table

**Status**: Accepted
**Date**: 2025-10-06
**Updated**: 2026-04-18

## Context

- ADR‑001 fixed primitives (X25519/HKDF/XChaCha20‑Poly1305/Ed25519).
- Need a deterministic wire format for pod→gateway telemetry and a simple, verifiable replay policy for intermittent
  links.
- Frames must be compact (\<= ~48 bytes typical), parseable on tiny MCUs, and easy to test with vectors.

## Decision

- **Frame type:** Compact binary record with fixed header + AEAD payload
- **Endianness:** Network byte order (big‑endian) for integers
- **AAD (associated data):** `dev_id || msg_type` (2 B + 1 B)
- **Current nonce layout:** XChaCha20-Poly1305 nonce bytes are
  `salt8 || fc32_as_u64_be || tail8`. `salt8` is provisioned per device,
  `fc32_as_u64_be` binds the 32-bit frame header counter into the nonce by
  encoding `u64::from(fc)` as eight big-endian bytes, and `tail8` remains
  producer-specific uniqueness material.
- **Profile boundary:** the supported AEAD plaintext profile is
  `rust-postcard-v1`: a postcard-encoded `trackone-core::Fact` decoded by the
  native Rust gateway boundary.
- **Commitment boundary:** Postcard is not the public interoperability
  contract. Accepted frames are projected into canonical facts, then committed
  as deterministic CBOR under `trackone-canonical-cbor-v1`.

### M#2 Implementation Note (Test Harness)

For test harness and initial development, we use **ChaCha20-Poly1305** with a **96-bit nonce** (12 bytes):

- Nonce: `salt4 || fc32 || rand4`
  - `salt4`: per‑device random salt (4 bytes)
  - `fc32`: 32-bit frame counter
  - `rand4`: 4-byte random

Production deployment will use **XChaCha20-Poly1305** with **192-bit nonce** (24 bytes):

- Nonce: `salt8 || fc32_as_u64_be || rand8`
  - `salt8`: per‑device random salt (8 bytes)
  - `fc32_as_u64_be`: 32-bit frame header counter expanded with
    `u64::from(fc)` and encoded as 8 big-endian bytes
  - `rand8`: 8-byte random

This allows test development with standard ChaCha20-Poly1305 while planning for XChaCha's extended nonce space in
production.

- **Frame layout (v1):**
  - `dev_id`: u16
  - `msg_type`: u8 (0=telemetry, 1=alert, 2=ack, 3=cfg_ack)
  - `fc`: u32 (frame counter)
  - `flags`: u8 (bitfield; e.g., low_power, flood, anomaly)
  - `payload_ct`: ciphertext carrying postcard `Fact` plaintext
  - `tag`: 16 B (Poly1305)
  - **Total typical:** 2 + 1 + 4 + 1 + (16–24) + 16 = 40–48 B

## Payload (inside AEAD)

- `rust-postcard-v1`: Postcard-encoded `trackone-core::Fact` for the Rust
  pod/native path.
- Gateway admission projects accepted postcard facts into the canonical fact
  shape. The authoritative commitment bytes are the resulting `.cbor`
  artifacts, not the AEAD plaintext representation.

## Replay Policy

- Gateway maintains `device_table[dev_id]`:
  - `highest_fc_seen` (u32 for M#2, u64 for production)
  - `fc_window` (default 64; accept if `|fc - highest_fc_seen| <= window_size`)
  - `salt4`/`salt8` for nonce reconstruction
  - `ck_up` (32-byte AEAD key)
- On receipt:
  1. Validate nonce prefix/counter against stored salt and header frame counter
  1. Verify AEAD with AAD = `dev_id || msg_type`; if fails → drop
  1. Decode the selected plaintext profile; if profile semantics conflict with
     the frame header → drop
  1. Check replay window; if duplicate or outside window → drop and log
  1. If accepted → update `highest_fc_seen`, persist device_table
- **FC rollback handling:**
  - If `fc < highest_fc_seen` and not within window: mark device "stale"; require re‑provision

## Device Table (Gateway)

- **Fields (per device_id):**
  - `salt4` (M#2) or `salt8` (production): nonce salt
  - `ck_up`: 32-byte uplink AEAD key
  - `highest_fc_seen`: last accepted frame counter
  - `last_seen`: ISO8601 timestamp
  - `msg_type`, `flags`: from last frame
- **Storage:** JSON with atomic writes; encrypted at rest if needed

## Key Rotation (Future)

- Signed rotate command sets `epoch=E`; both sides derive `CK' = HKDF‑Expand(PRK, "rotate:epoch=E", 32)`, `fc` resets to
  0

## Rationale

- Compact header keeps overhead low; native Rust postcard admission avoids
  re-defining protocol semantics independently in Python and Rust.
- 96-bit nonce (M#2) or 192-bit nonce (production) balances determinism (replay defense) and entropy.
- Windowed acceptance tolerates reordering and brief disconnects without keeping unbounded history.
- The deterministic CBOR boundary keeps public commitments stable while allowing
  transport/plaintext encodings to migrate.

## Testing (M#2 Implemented)

- Deterministic AEAD vectors with fixed key/nonce/AAD and known ct/tag
- Replay window edge cases: accept at +64, reject at +65, duplicate rejection across restart
- Postcard framed-admission regression tests for AAD, nonce, replay, and
  canonical fact projection
- Tamper resistance: modified ct/tag/AAD/nonce-length all rejected

## Operational Notes

- Persist `highest_fc_seen` atomically to avoid accepting stale frames after gateway restarts.
- Log rejected frames with reasons (AEAD fail, replay, stale) for outage analysis.
- Device table persisted to JSON; verifier reloads on restart to maintain replay state.

## Status Rationale

- Matches threat model and resource constraints; easy to implement and audit; aligns with ADR‑001 primitives and the
  ledger/OTS pipeline.
- M#2 implementation complete with ChaCha20-Poly1305; production migration to XChaCha straightforward.
