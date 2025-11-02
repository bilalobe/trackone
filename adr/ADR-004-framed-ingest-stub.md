# ADR-004: Framed Ingest Stub for M#1 (Plaintext CT for Pipeline Bring‑up)

Status: Accepted
Date: 2025-10-08

## Context

Milestone #1 focuses on end‑to‑end integration: ingest framed telemetry, enforce a replay window, produce canonical
facts, and batch/anchor/verify daily artifacts. To de‑risk integration, we intentionally postpone on‑pod AEAD to M#2 and
use a **stub** ciphertext.

This ADR documents the temporary choices so reviewers don’t confuse the M#1 stub with the ADR‑001/002 security design.

## Decision

For M#1 only:

- **Frame shape (transport/NDJSON)**
  Each line is a JSON object:
  ```json
  {
    "hdr":   { "dev_id": u16, "msg_type": u8, "fc": u32, "flags": u8 },
    "nonce": "base64(24B)",     // placeholder random
    "ct":    "base64( utf8(JSON payload) )",  // plaintext payload bytes
    "tag":   "base64(16B)"      // placeholder random
  }
  ```
- **Replay window (enforced):**
  Gateway maintains `highest_fc_seen` per `dev_id` and accepts a frame iff `0 < fc - highest_fc_seen ≤ window` (default
  64). First frame for a device is accepted if `fc ≥ 0`.

- **Decryption (stub):**
  Gateway decodes `ct` as UTF‑8 and parses JSON into the `payload`. No cryptographic verification is performed in M#1.

- **Canonical facts:**
  Gateway writes canonical fact JSON:
  ```json
  { "device_id": "pod-XYZ", "timestamp": "<gateway-utc-iso>", "nonce": "<base64-24B>", "payload": {...} }
  ```
  Facts are validated against `fact.schema.json` (warn‑only by default).

- **Batch/anchor/verify:**
  `merkle_batcher.py --validate-schemas` builds block/day artifacts; `ots_anchor.py` stamps the day blob (placeholder
  proof allowed); `verify_cli.py` recomputes root and checks the proof.

## Consequences

- **Security:** M#1 transport is **not confidential nor authenticated**. It is a lab/CI stub only. Replay window logic
  is active and tested, but tag/nonce are placeholders.
- **Integration:** We can exercise the entire pipeline (framed ingest → facts → Merkle → OTS → verify) with
  deterministic artifacts and CI.
- **Clarity:** This ADR prevents confusion by explicitly stating that `ct/tag` are stubs and will be replaced.

## Migration (M#2 Plan)

- Replace the stub with AEAD per ADR‑001/002:
    - Nonce: XChaCha 24B = `salt8 || fc64 || rand8`
    - AAD: `dev_id || msg_type`
    - Payload: compact TLV inside AEAD ciphertext
    - Tag: Poly1305 (16B)
- Add test vectors: (Ng, Np, Tpod, B, eP/eG → PRK → CK_up/down → nonce/AAD/plain → cipher/tag).
- Enforce AEAD verification in gateway; invalid tag → drop + log.
- Keep the **same** header fields and replay window policy; only `ct/tag` semantics change.

## Alternatives Considered

- Implement AEAD immediately in M#1
  Pros: early security; Cons: longer bring‑up, more moving parts to debug simultaneously.
- Use binary CBOR framing in M#1
  Pros: compact; Cons: less readable for tests; JSON NDJSON is faster for iteration.

## Testing

- `tests/test_framed_ingest.py` covers:
    - Accept path with increasing `fc`
    - Duplicate/out‑of‑window rejection
    - End‑to‑end: frames → facts → batch → (OTS) → verify
- CI runs `pytest` and a one‑shot pipeline (`make run`).

## Status Rationale

This ADR formalizes the temporary plaintext framing so reviewers can approve M#1 while expecting M#2 to swap in the AEAD
defined in ADR‑001/002 without changing headers, replay policy, or downstream batching/anchoring.
