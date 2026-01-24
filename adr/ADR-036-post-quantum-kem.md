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

As identified in ADR-001 (under the PQC roadmap, e.g., Kyber), exploring post-quantum (PQ) key agility is a planned enhancement. The motivation is "hedging": retaining security if either classical ECDH or the PQ primitive later weakens.

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

- Hybrid secret: `ss_ecdh` (from X25519) and `ss_kem` (from ML-KEM) are combined in the KDF; the remainder of this subsection describes how `ss_kem` is established.

#### Deployment models for ML-KEM

There are two deployment models for the ML-KEM keypair used during provisioning:

1. **Pod long-term ML-KEM key (recommended)**  
   - **Key ownership / storage:**  
     - Each pod generates a long-term ML-KEM keypair `(pk_pq, sk_pq)` during manufacturing or first boot.  
     - `pk_pq` is registered in the device registry alongside the pod's Ed25519 verification key.  
     - `sk_pq` is stored only on the pod and never leaves the device.  
   - **Provisioning flow:**  
     - Gateway looks up `pk_pq` from the registry.  
     - Gateway encapsulates to `pk_pq` producing `(ct_kem, ss_kem)`.  
     - Pod decapsulates `ct_kem` with its `sk_pq` to derive the same `ss_kem`.  
   - **Security properties:**  
     - Stable post-quantum identity for the pod, analogous to the existing Ed25519 verification key.  
     - Clear separation of roles: gateway never holds long-term PQ private keys.  
     - Compromise of a gateway does not retroactively expose past `ss_kem` values (assuming ML-KEM KDM security and proper erasure of ephemeral state).  
   - **Operational characteristics:**  
     - Requires maintaining `pk_pq` in the registry (similar to Ed25519).  
     - No additional provisioning round trips compared to current flow.  
     - Key rotation is explicit: rotating `pk_pq` requires updating registry state and may be tied to device lifecycle events.  
   - **When to use:**  
     - Default for production deployments where pods can safely store long-term PQ keys.  
     - Recommended whenever registry integration is available, as it avoids ambiguity about pod identity and simplifies auditing.

2. **Gateway-ephemeral ML-KEM keypair**  
   - **Key ownership / storage:**  
     - Gateway generates an ephemeral ML-KEM keypair `(pk_pq, sk_pq)` per provisioning session.  
     - The pod either uses a KEM mechanism that allows encapsulation to the gateway's `pk_pq` or otherwise receives `pk_pq` as part of the provisioning transcript.  
     - `sk_pq` is held only by the gateway for the duration of the session and then erased.  
   - **Provisioning flow:**  
     - Gateway generates `(pk_pq, sk_pq)` at the start of the session.  
     - Pod encapsulates to `pk_pq`, producing `(ct_kem, ss_kem)`.  
     - Gateway decapsulates `ct_kem` with `sk_pq` to derive the same `ss_kem`.  
   - **Security properties:**  
     - No long-term PQ private key on the pod; all PQ secrets on the gateway are ephemeral to the session.  
     - Does **not** provide a stable PQ identity for the pod; identity continues to rely solely on existing Ed25519 keys.  
     - Slightly larger attack surface on gateway infrastructure, which handles more cryptographic state, but without long-lived PQ key material.  
   - **Operational characteristics:**  
     - Does not require storing `pk_pq` in the device registry.  
     - May introduce a minor amount of additional orchestration complexity (ensuring `pk_pq` is correctly communicated and bound to the session).  
     - Simpler pod implementation if persistent PQ key storage is not yet available.  
   - **When to use:**  
     - Transitional environments where pods cannot yet provision or persist a long-term ML-KEM keypair.  
     - Test, lab, or constrained deployments where avoiding any new registry fields is a priority.

In both models, the encapsulation/decapsulation steps are:

- During provisioning, one side encapsulates to the other's `pk_pq` producing `(ct_kem, ss_kem)`.
- The other side decapsulates `ct_kem` with its `sk_pq` yielding the same `ss_kem`.
- In the preferred model (pod has long-term `pk_pq`): the gateway encapsulates to the pod's `pk_pq`, producing `(ct_kem, ss_kem)` and sending `ct_kem` in the provisioning transcript; the pod decapsulates `ct_kem` with its `sk_pq` to recover `ss_kem`.

The **recommended deployment model** for production is the **pod long-term ML-KEM key** model, as it aligns with existing Ed25519 verification key handling, reduces provisioning round trips, and avoids ambiguity about post-quantum pod identity. The gateway-ephemeral model is supported but should be treated as a compatibility or migration path rather than the default.

### Transcript Additions

Provisioning transcript MUST include, for hybrid mode:

- `kex_suite = x25519+mlkem`
- `ct_kem` (the ML-KEM ciphertext)
- a string field `pq_param_id` containing the PQ parameter set identifier (e.g., `"mlkem_768"`) to prevent cross-suite confusion

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
- X25519 produces a 32-byte `ss_ecdh`, and ML-KEM-768 (recommended) produces a 32-byte `ss_kem`, yielding `ikm` of length 64 bytes; if a different PQ KEM or parameter set is used, implementers MUST ensure both inputs remain fixed-length and ordered before relying on this concatenation construction.
- Additional suite label mixed into `salt_h` provides robust domain separation and prevents accidental cross-mode key reuse.

### Failure Handling

- If ML-KEM decapsulation detects malformed input (e.g., incorrect ciphertext length for the parameter set), provisioning MUST abort (do not fall back silently).
- If `kex_suite` mismatches between parties, abort.
- No "opportunistic downgrade": gateway/operator policy controls `kex_suite`; mismatches are considered errors.

## Consequences

Benefits:

- Hedge against future quantum attacks on X25519 by adding a PQ secret.
- Limits blast radius: telemetry framing, replay policy, and AEAD construction stay unchanged.
- Clear auditability: the transcript explicitly records the suite and PQ ciphertext.

Costs:

- Larger provisioning transcript: for ML-KEM-768, the PQ ciphertext `ct_kem` adds 1088 bytes (and the PQ public key `pk_pq` is 1184 bytes) compared to the current X25519-only flow. This is a significant but one-time cost during device onboarding and does not affect regular telemetry frames, which remain within the 40–60 byte target from ADR-001.
- More implementation and test surface (new primitive, vector generation, negative tests).
- Requires dependency support (PyNaCl/libsodium may not expose ML-KEM; may require Rust `trackone-core` or another vetted binding).

## Implementation Notes (Non-Normative)

- If ML-KEM is not available in PyNaCl/libsodium in this environment, implement hybrid provisioning first in Rust (`trackone-core`) and expose to Python via FFI (ADR-017 path), with equivalence tests and deterministic vectors.
- Add deterministic vectors to `toolset/unified/crypto_test_vectors.json` for:
  - X25519-only provisioning (baseline)
  - Hybrid provisioning (`mlkem_768` recommended starting point: NIST Level 3, roughly matching X25519's ~128-bit classical security while keeping ciphertext/key sizes and CPU cost acceptable for ultra-low-power pods; `mlkem_512` would under-shoot this target and `mlkem_1024` increases bandwidth/CPU without clear benefit for the current threat model)
- Ensure all random generation uses CSPRNG per ADR-018.

## Security Considerations

- This ADR provides "at least one holds" security assuming the HKDF combiner and domain separation are used as specified.
- Hybrid does not help if endpoint keys are compromised (pod/gateway fully owned).
- A downgrade attack is mitigated by:
  - including `kex_suite` in the signed transcript
  - enforcing operator policy (reject weaker suite when hybrid is mandated)

### Long-term ML-KEM key management (pods)

- Key storage:
  - Each pod that participates in ML-KEM-based hybrid provisioning holds a long-term ML-KEM keypair (`pk_pq`, `sk_pq`), with `pk_pq` registered in the provisioning registry.
  - `sk_pq` MUST be stored only in device-provided or OS-provided protected storage (e.g., TPM/secure element, hardware-backed keystore, or an encrypted software keystore bound to the device) and MUST NOT be exported in plaintext off the device.
  - `sk_pq` MUST NEVER be logged, included in telemetry, or transmitted over any channel.
- Key rotation:
  - ML-KEM long-term keys SHOULD be rotated periodically or on operator demand, reusing the key rotation mechanisms and operational procedures defined in ADR-001 for channel keys (e.g., versioned keys, rollout windows).
  - Rotation consists of: generating a new ML-KEM keypair on the pod, registering the new `pk_pq` (with a new key identifier) in the registry, and phasing out use of the old key according to operator policy.
  - Rotation MUST NOT require full device reprovisioning; pods MUST support updating their registered `pk_pq` while preserving their existing identity and attestations.
- Compromise handling:
  - If `sk_pq` is suspected or confirmed to be compromised, the corresponding `pk_pq` in the registry MUST be marked revoked/compromised, and new provisioning or channel establishment requests using that key MUST be rejected.
  - After remediation on the device, a fresh ML-KEM keypair MUST be generated and registered before the pod resumes hybrid provisioning.
  - Compromise of `sk_pq` does not weaken past sessions that used an independent classical ECDH key under the "at least one holds" model, but future confidentiality for that pod MUST be considered lost until rotation is completed.

## Acceptance Criteria

- Documentation:
  - `src/includes/crypto_design.tex` is updated to reference ADR-036, describing the optional hybrid provisioning mode at a high level and explaining its relationship to the PQC roadmap (Dilithium/Kyber at gateways) mentioned in ADR-001.
- Tests:
  - Deterministic test vectors validate both suites.
  - Negative tests: suite mismatch, modified `ct_kem`, decapsulation failure, transcript tampering.
- Compatibility:
  - Existing `x25519` provisioning continues to work unchanged unless hybrid is explicitly enabled.
