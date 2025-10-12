# ADR-002: Telemetry Framing, Nonce/Replay Policy, and Device Table

**Status:** Accepted
**Date:** 2025-10-06

## Context

- ADR‑001 fixed primitives (X25519/HKDF/XChaCha20‑Poly1305/Ed25519).
- Need a deterministic wire format for pod→gateway telemetry and a simple, verifiable replay policy for intermittent
  links.
- Frames must be compact (≤ ~48 bytes typical), parseable on tiny MCUs, and easy to test with vectors.

## Decision

- **Frame type:** Compact binary record with fixed header + AEAD payload
- **Endianness:** Network byte order (big‑endian) for integers
- **AAD (associated data):** `dev_id || msg_type` (2 B + 1 B)
- **Nonce:** 24 bytes (XChaCha) assembled as `salt8 || fc8 || rand8`
    - `salt8`: per‑device random salt set at provisioning; stored alongside keys
    - `fc8`: 64‑bit frame counter, monotonic per device
    - `rand8`: 64‑bit random from DRBG (prevents structural patterns)
- **Frame layout (v1):**
    - `dev_id`: u16
    - `msg_type`: u8 (0=telemetry, 1=alert, 2=ack, 3=cfg_ack)
    - `fc`: u32 (low 32 bits of the 64‑bit counter; full 64 carried in nonce)
    - `flags`: u8 (bitfield; e.g., low_power, flood, anomaly)
    - `payload_ct`: 16–24 B ciphertext (variable, compact TLV inside)
    - `tag`: 16 B (Poly1305)
    - **Total typical:** 2 + 1 + 4 + 1 + (16–24) + 16 = 40–48 B

## Payload (inside AEAD)

- Minimal TLV to keep evolvable:
    - t=0x01 cov1%, t=0x02 cov2% (u8)
    - t=0x03 fosc_mHz (u16), t=0x04 amp_uV (u16)
    - t=0x05 rh_pct (u8), t=0x06 t_tenthsC (i16)
    - t=0x07 status_flags (u8)
- Gateway decodes TLV into a Fact; schema defined in `fact.schema.json`

## Replay Policy

- Gateway maintains `device_table[dev_id]`:
    - `highest_fc_seen` (u64)
    - `fc_window` (e.g., accept if 0 < fc64 − highest_fc_seen ≤ 64)
    - `salt8` for nonce reconstruction
- On receipt:
    1. Rebuild nonce from (`salt8`, `fc64`, `rand8` extracted from header/nonce field)
    2. Verify AEAD; if fails → drop
    3. Check replay window; if stale or duplicate → drop and log
    4. If accepted → update `highest_fc_seen`
- **FC rollback handling:**
    - If `fc64 < highest_fc_seen` and not within window: mark device “stale”; require signed rotate or re‑provision at
      next service

## Device Table (Gateway)

- **Fields (per device_id):**
    - `pkp_fingerprint` (Ed25519), state (active/revoked/stale)
    - `salt8` (nonce salt), `highest_fc_seen` (u64), `last_seen_ts`
    - `epoch` (rotation index), corridor/site
- **Storage:** JSON/CBOR with periodic snapshots; encrypted at rest if needed

## Key Rotation (Reminder)

- Signed rotate command sets `epoch=E`; both sides derive `CK’ = HKDF‑Expand(PRK, “rotate:epoch=E”, 32)`, `fc64` resets
  to 0; device table window resets

## Rationale

- Compact header keeps overhead low; TLV payload allows adding fields without breaking parsers.
- 24‑byte XChaCha nonce with salt+fc+rand balances determinism (replay defense) and entropy (pattern hiding).
- Windowed acceptance tolerates reordering and brief disconnects without keeping unbounded history.

## Alternatives Considered

- 96‑bit nonce (ChaCha20‑Poly1305) with (salt4||fc8): tighter space and more collision risk; rejected in favor of
  XChaCha.
- JSON frames: human‑friendly but larger and slower to parse on MCU.
- Full 64‑bit fc field in header: +4 bytes; we carry low 32 B for diagnostics, keep full 64 in nonce to save header
  space.

## Consequences

- Simple, fast parsing on MCU and gateway.
- Deterministic replay behavior suitable for audits.
- Precise test vectors can be authored (nonce assembly, AAD, fc window).

## Testing

- Provide vectors with:
    - `salt8`, `fc64`, `rand8` → nonce
    - AAD + plaintext → ciphertext/tag
    - Replay window accept/reject cases (edge: boundary at +64)
- Fuzz parsers for TLV robustness.

## Operational Notes

- Persist `highest_fc_seen` atomically to avoid accepting stale frames after gateway restarts.
- Log rejected frames with reasons (AEAD fail, replay, stale) for outage analysis.
- For multi‑site deployments, namespace `dev_id` per corridor or include corridor in AAD.

## Status Rationale

- Matches power and size constraints; easy to implement; aligns with ADR‑001 primitives and the ledger/OTS pipeline.
