# ADR-036: Post-Quantum Hybrid Provisioning (X25519 + ML-KEM/Kyber)

- Status: Proposed
- Date: 2026-01-22
- Related:
  - ADR-001: Cryptographic Primitives
  - ADR-005: PyNaCl Migration
  - ADR-006: Forward-only Schema and salt8
  - ADR-018: Cryptographic Randomness and Nonce Policy

## Context

TrackOne provisioning currently derives `CK_up`/`CK_down` from an ephemeral X25519 ECDH shared secret via HKDF-SHA256, with a non-secret `salt = SHA-256(Ng || Np || T_pod || B)` as documented in `src/includes/crypto_design.tex`.

There is an explicit TODO to explore post-quantum (PQ) key agility (e.g., Kyber hybrid). The motivation is “hedging”: retaining security if either classical ECDH or the PQ primitive later weakens.

Constraints:

- Current authoritative implementation uses PyNaCl/libsodium.
- Telemetry framing and replay semantics must not change.
- Provisioning transcript is already signed with Ed25519 and verified by gateway.

## Decision

Introduce an optional **hybrid provisioning mode** that combines:

- Classical: X25519 ECDH shared secret `ss_ecdh`
- Post-quantum: ML-KEM (Kyber) shared secret `ss_kem` via encapsulation/decapsulation

The hybrid mode derives the same `CK_up` and `CK_down` sizes and keeps the telemetry nonce/AAD rules unchanged. Only provisioning transcript content and key derivation inputs change.

### Versioning / Negotiation

- Add a provisioning parameter `kex_suite` with values:
  - `x25519` (current default)
  - `x25519+mlkem` (hybrid)
- Device table schema remains forward-only; introduce a new `_meta.kex_suite` field.
- If `kex_suite` is absent, treat as `x25519` for backward compatibility during rollout.

## Design Details

### PQ Component

For `x25519+mlkem`:

- Gateway generates ML-KEM keypair `(pk_pq, sk_pq)` or obtains pod’s `pk_pq` depending on deployment model.
- Preferred model: pod has a long-term ML-KEM public key in registry, similar to Ed25519 verification key usage (reduces provisioning round trips, avoids ephemeral PQ identity confusion).
- During provisioning, one side encapsulates to the other’s `pk_pq` producing `(ct_kem, ss_kem)`.
- The other side decapsulates `ct_kem` with its `sk_pq` yielding the same `ss_kem`.

### Transcript Additions

Provisioning transcript MUST include, for hybrid mode:

- `kex_suite = x25519+mlkem`
- `ct_kem` (the ML-KEM ciphertext)
- identifiers for PQ parameter set (e.g., `mlkem_768`) to prevent cross-suite confusion

The transcript remains Ed25519-signed by the pod and verified by the gateway. Any mismatch in `ct_kem`/suite invalidates signature verification or derived keys.

### Combiner / Key Derivation

Keep existing `salt = SHA-256(Ng || Np || T_pod || B)`.

Derive PRK using HKDF-Extract with explicit domain separation:

- Let `ikm = ss_ecdh || ss_kem`
- Let `salt_h = SHA-256(salt || "barnacle:kex:x25519+mlkem")`
- `PRK = HKDF-Extract(salt_h, ikm)`

Then derive channel keys unchanged (but fixed labels):

- `CK_up   = HKDF-Expand(PRK, "barnacle:up",   32)`
- `CK_down = HKDF-Expand(PRK, "barnacle:down", 32)`

Rationale:

- Concatenation inside HKDF-Extract is acceptable when both secrets have fixed lengths and are clearly ordered.
- Additional suite label mixed into `salt_h` provides robust domain separation and prevents accidental cross-mode key reuse.

### Failure Handling

- If ML-KEM decapsulation fails (implementation-defined), provisioning MUST abort (do not fall back silently).
- If `kex_suite` mismatches between parties, abort.
- No “opportunistic downgrade”: gateway/operator policy controls `kex_suite`; mismatches are considered errors.

## Consequences

Benefits:

- Hedge against future quantum attacks on X25519 by adding a PQ secret.
- Limits blast radius: telemetry framing, replay policy, and AEAD construction stay unchanged.
- Clear auditability: the transcript explicitly records the suite and PQ ciphertext.

Costs:

- Larger provisioning transcript (adds `ct_kem` and suite metadata).
- More implementation and test surface (new primitive, vector generation, negative tests).
- Requires dependency support (PyNaCl/libsodium may not expose ML-KEM; may require Rust `trackone-core` or another vetted binding).

## Implementation Notes (Non-Normative)

- If ML-KEM is not available in PyNaCl/libsodium in this environment, implement hybrid provisioning first in Rust (`trackone-core`) and expose to Python via FFI (ADR-017 path), with equivalence tests and deterministic vectors.
- Add deterministic vectors to `toolset/unified/crypto_test_vectors.json` for:
  - X25519-only provisioning (baseline)
  - Hybrid provisioning (`mlkem_768` recommended starting point)
- Ensure all random generation uses CSPRNG per ADR-018.

## Security Considerations

- This ADR provides “at least one holds” security assuming the HKDF combiner and domain separation are used as specified.
- Hybrid does not help if endpoint keys are compromised (pod/gateway fully owned).
- A downgrade attack is mitigated by:
  - including `kex_suite` in the signed transcript
  - enforcing operator policy (reject weaker suite when hybrid is mandated)

## Acceptance Criteria

- Documentation:
  - `src/includes/crypto_design.tex` TODO is resolved by referencing ADR-036 and describing the hybrid derivation at a high level.
- Tests:
  - Deterministic test vectors validate both suites.
  - Negative tests: suite mismatch, modified `ct_kem`, decapsulation failure, transcript tampering.
- Compatibility:
  - Existing `x25519` provisioning continues to work unchanged unless hybrid is explicitly enabled.
