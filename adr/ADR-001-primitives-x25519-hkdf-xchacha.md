# ADR-001: Cryptographic Primitives and Framing

**Status**: Accepted
**Date**: 2025-10-06
**Updated**: 2026-04-19

## Context

- We need a secure, auditable telemetry pipeline between ultra–low‑power pods and a gateway with intermittent links.
- Constraints:
  - Tiny payloads (\<= 40–60 bytes typical)
  - Low compute/energy on MCU-class devices
  - Simple nonce management with replay protection
  - Deterministic verification and public timestamp anchoring (OpenTimestamps)
- Deliverables must be portable across languages (pod firmware, Python gateway) and easy to test with vectors.

## Decision

**Primitives:** TrackOne keeps the primitives below. The historical
Python-first implementation-library decision that made PyNaCl the primary
runtime dependency is superseded by
[ADR-049](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md).
For supported evidence-plane runtime paths, `trackone_core` is the stable
Python-facing authority boundary.

- **Key agreement:** X25519 (ECDH over Curve25519)
  - Used during provisioning (ephemeral+static) to derive channel secrets.
  - Implementation authority: lifecycle/control-plane dependent until a
    supported `trackone_core` provisioning surface exists.
- **KDF:** HKDF-SHA256 (RFC 5869)
  - HKDF‑Extract with a salt; HKDF‑Expand with context strings to derive uplink/downlink keys.
  - Implementation authority: lifecycle/control-plane dependent until a
    supported `trackone_core` provisioning surface exists.
- **AEAD (192-bit nonce):** XChaCha20‑Poly1305
  - Encrypts telemetry payloads; provides integrity and confidentiality with 192‑bit nonce.
  - Implementation authority: `trackone_core.crypto` for supported
    evidence-plane framed admission.
- **AEAD (96-bit nonce):** ChaCha20-Poly1305 (IETF variant)
  - Used in tests and compatibility scenarios requiring 12-byte nonces.
  - Implementation authority: dev/test or explicit compatibility tooling only.
- **Signatures:** Ed25519
  - Pod identity and config/firmware authenticity; gateway block header signatures.
  - Implementation authority: optional publication/lifecycle tooling until a
    supported `trackone_core` signing surface exists.
- **Hash:** SHA‑256
  - Merkle leaves/roots, day blobs (for OTS), and auxiliary digests.
  - Implementation authority: `trackone_core.ledger` and `trackone_core.merkle`
    for evidence-plane commitments.

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
- X25519 ephemeral ECDH (eP\<->eG), optional static+ephemeral hybrid.
- `PRK = HKDF‑Extract(salt = SHA‑256(Ng||Np||Tpod||B), IKM = ECDH secret(s))`
- `CK_up = HKDF‑Expand(PRK, "barnacle:up", 32)`
- `CK_down = HKDF‑Expand(PRK, "barnacle:down", 32)`
- Pod signs transcript with Ed25519; gateway verifies with PKP (from QR/onboard registry).

## Replay and Rotation

- **Replay protection:** gateway tracks the highest FC per device with a sliding acceptance window (e.g., 64).
- **Key rotation:** signed "rotate" command from gateway; derive `CK' = HKDF‑Expand(PRK, "rotate:epoch=E", 32)`; persist
  new epoch and reset the replay window.
  +**Key rotation automation:** roadmap for the rotation workflow exists (signed rotate command, HKDF-based epoch derivation), but automation is not yet wired. Long-term deployments must perform these updates manually until the M#5 "weekly ratcheting" target (tagged as `0.0.1+N-m5`) delivers the scheduled, automated rotation service; future ADRs will codify how and where the automation runs.
  +**Weekly ratchet fulfillment (ADR-022):** the `Weekly Ratchet` GitHub Actions workflow now exercises `tox -e ots-cal`, `tox -e ots`, and `tox -e slow` with `RUN_REAL_OTS=1`, tags the successful run as `v0.0.1+N-m5`, and uploads a `ratchet.json` artifact detailing the CI run, calendars, and milestones. Operators should treat the latest tag as the canonical epoch reference when scheduling manual rotations or validating anchor freshness; missing tags signal that fallback/manual rotation must occur.

## Ledger Interface (non‑secret decisions)

- **Facts:** verified, decrypted payloads are normalized to canonical JSON/CBOR and hashed with SHA‑256 as Merkle
  leaves.
- **Block headers:** Ed25519 signature by gateway.
- **Day artifact:** canonical CBOR (site_id, date, prev_day_root, batches[], day_root); SHA‑256(day.cbor) anchored via
  OpenTimestamps.

## Consequences

- **Security:** Modern, audited primitives with minimal foot‑guns; forward secrecy via ephemeral ECDH; robust AEAD with
  long nonce.
- **Simplicity:** AEAD frames are small; nonce assembly deterministic; HKDF context strings document key purpose.
- **Portability:** libsodium implementations exist in C, Rust, Go, Python; feasible on Cortex‑M0+/M3.
- **Auditability:** Clear separation of secret frames and public hashes/anchors; easy to produce vectors and proofs.
- **Performance:** native `trackone_core` evidence-plane helpers avoid Python
  crypto on the supported hot path.
- **Consistency:** protocol-critical evidence-plane operations have one stable
  Python-facing authority boundary instead of direct script-level crypto calls.

## Alternatives Considered

- **AES‑GCM:** +HW acceleration on some MCUs; −strict 96‑bit nonce discipline; higher risk if counters ever collide.
- **ChaCha20‑Poly1305 (96‑bit nonce):** acceptable; −tighter nonce space than XChaCha.
- **P‑256 ECDH/ECDSA:** acceptable; +HW on some chips; −implementation complexity vs Ed25519/X25519 on MCUs.
- **cryptography package:** Previous Python-first choice; replaced by PyNaCl in
  the ADR-005 phase, with current runtime dependency strategy superseded by
  ADR-049.

## Migration Notes (2025-10-12)

Migrated from mixed `cryptography` + `pynacl` to `pynacl` only in the
Python-first phase:

- **Removed:** `cryptography.hazmat.primitives.*` dependencies
- **Benefits:** Single crypto library, better performance, cleaner API
- **Compatibility:** All test vectors regenerated with PyNaCl; backward compatibility maintained
- **See:** ADR-005 for historical migration rationale and ADR-049 for current
  runtime dependency strategy.

## Non‑decisions (future ADRs)

- Exact wire encoding (CBOR vs. compact binary) of frames and device table format.
- PQC roadmap (Dilithium/Kyber) at gateways; pods remain classic.
- BLE/UART provisioning vs LoRa bootstrap.

## Testing and Vectors

- Provide end‑to‑end test vectors: (Ng, Np, Tpod, B, eP/eG, PRK, CK_up/down, nonce, aad, plain, cipher, tag).
- Interop tests between pod simulator and Python verifier.
- Historical test vectors were generated with PyNaCl for deterministic,
  reproducible results. Current supported framed/evidence runtime checks should
  exercise `trackone_core` authority.

## Operational Notes

- Persist only: dev_id, CK_up/down, FC, PKP fingerprint (no long‑term salts/nonces).
- Reject downlinks with stale epochs or bad AEAD tags/signatures.
- Treat RTC and bio‑hash strictly as non‑secret salt; secrecy rests on ECDH and HKDF.

## Status Rationale

- Meets threat model and resource constraints; easy to implement and audit; aligns with verifiable ledger flow.
- Primitive choices remain accepted. Runtime dependency authority is updated by
  ADR-049.
