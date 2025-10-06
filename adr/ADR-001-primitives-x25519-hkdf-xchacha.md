# ADR-001: Cryptographic Primitives and Framing for Track 1`

**Status:** Accepted  
**Date:** 2025-10-06

## Context

- We need a secure, auditable telemetry pipeline between ultra–low‑power pods and a gateway with intermittent links.
- Constraints:
    - Tiny payloads (≤ 40–60 bytes typical)
    - Low compute/energy on MCU-class devices
    - Simple nonce management with replay protection
    - Deterministic verification and public timestamp anchoring (OpenTimestamps)
- Deliverables must be portable across languages (pod firmware, Python gateway) and easy to test with vectors.

## Decision

- **Key agreement:** X25519 (ECDH over Curve25519)
    - Used during provisioning (ephemeral+static) to derive channel secrets.
- **KDF:** HKDF (RFC 5869) with SHA‑256
    - HKDF‑Extract with a salt; HKDF‑Expand with context strings to derive uplink/downlink keys.
- **AEAD:** XChaCha20‑Poly1305 (libsodium compact framing)
    - Encrypts telemetry payloads; provides integrity and confidentiality with a 192‑bit nonce.
- **Signatures:** Ed25519
    - Pod identity and config/firmware authenticity; gateway block header signatures.
- **Hash:** SHA‑256
    - Merkle leaves/roots, day blobs (for OTS), and auxiliary digests.

## Telemetry Frame (v1, logical)

- `dev_id`: 2 B (u16)
- `fc`: 4 B (u32 frame counter, monotonic per device)
- `flags`: 1 B
- `nonce` (XChaCha, 24 B) assembled from: `salt8 || fc8 || rand8`
- `aad = dev_id || msg_type`
- `ciphertext = AEAD(plain_payload, aad, nonce, key=CK_up)`
- `tag`: 16 B

**Notes:** Frame layout on wire will be specified in the implementation guide; test vectors will include
nonce/aad/plain/tag.

## Provisioning (v1)

- **Inputs:** Ng (gateway nonce), Np (pod nonce), RTC time Tpod (non‑secret), bio‑hash B (non‑secret salt), pod static
  key (Ed25519/X25519).
- X25519 ephemeral ECDH (eP↔eG), optional static+ephemeral hybrid.
- `PRK = HKDF‑Extract(salt = SHA‑256(Ng||Np||Tpod||B), IKM = ECDH secret(s))`
- `CK_up = HKDF‑Expand(PRK, “barnacle:up”, 32)`
- `CK_down = HKDF‑Expand(PRK, “barnacle:down”, 32)`
- Pod signs transcript with Ed25519; gateway verifies with PKP (from QR/onboard registry).

## Replay and Rotation

- **Replay protection:** gateway tracks highest FC per device with a sliding acceptance window (e.g., 64).
- **Key rotation:** signed “rotate” command from gateway; derive `CK’ = HKDF‑Expand(PRK, “rotate:epoch=E”, 32)`; persist
  new epoch and reset replay window.

## Ledger Interface (non‑secret decisions)

- **Facts:** verified, decrypted payloads are normalized to canonical JSON/CBOR and hashed with SHA‑256 as Merkle
  leaves.
- **Block headers:** Ed25519 signature by gateway.
- **Day blob:** canonical JSON (site_id, date, prev_day_root, batches[], day_root); SHA‑256(day.bin) anchored via
  OpenTimestamps.

## Consequences

- **Security:** Modern, audited primitives with minimal foot‑guns; forward secrecy via ephemeral ECDH; robust AEAD with
  long nonce.
- **Simplicity:** AEAD frames are small; nonce assembly deterministic; HKDF context strings document key purpose.
- **Portability:** Implementations exist in C, Rust, Go, Python; feasible on Cortex‑M0+/M3.
- **Auditability:** Clear separation of secret frames and public hashes/anchors; easy to produce vectors and proofs.

## Alternatives Considered

- **AES‑GCM:** +HW acceleration on some MCUs; −strict 96‑bit nonce discipline; higher risk if counters ever collide.
- **ChaCha20‑Poly1305 (96‑bit nonce):** acceptable; −tighter nonce space than XChaCha.
- **P‑256 ECDH/ECDSA:** acceptable; +HW on some chips; −implementation complexity vs Ed25519/X25519 on MCUs.

## Non‑decisions (future ADRs)

- Exact wire encoding (CBOR vs compact binary) of frames and device table format.
- PQC roadmap (Dilithium/Kyber) at gateways; pods remain classic.
- BLE/UART provisioning vs LoRa bootstrap.

## Testing and Vectors

- Provide end‑to‑end test vectors: (Ng, Np, Tpod, B, eP/eG, PRK, CK_up/down, nonce, aad, plain, cipher, tag).
- Interop tests between pod simulator and Python verifier.

## Operational Notes

- Persist only: dev_id, CK_up/down, FC, PKP fingerprint (no long‑term salts/nonces).
- Reject downlinks with stale epochs or bad AEAD tags/signatures.
- Treat RTC and bio‑hash strictly as non‑secret salt; secrecy rests on ECDH and HKDF.

## Status Rationale

- Meets threat model and resource constraints; easy to implement and audit; aligns with verifiable ledger flow.