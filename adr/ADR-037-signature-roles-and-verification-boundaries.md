# ADR-037: Signature Roles and Verification Boundaries (Who Signs What)

**Status**: Proposed
**Date**: 2026-01-24
**Related**: ADR-001 (Primitives + provisioning), ADR-019 (chain of trust / provisioning records), ADR-025 (signed policy), ADR-026 (OTA firmware), ADR-034 (canonical bytes), ADR-036 (hybrid provisioning transcript binding)

## Context

TrackOne uses multiple cryptographic signatures across the system (pods, gateways, optional peers, and manufacturing/registry inputs). Existing ADRs describe individual parts (e.g., “pod signs provisioning transcript”, “manufacturer signs provisioning record”, “gateway signs block headers”), but the repo lacked a single, unambiguous statement of:

- which artifact is signed by which actor,
- what bytes are covered by each signature (canonicalization),
- what each verifier must validate (and in what order),
- and what optional counter-signatures exist (mutual authentication vs. one-way).

This ambiguity is risky: implementers may sign the “wrong thing”, omit downgrade-resistance fields, or mis-attribute trust (especially as hybrid provisioning and policy signing expand).

## Decision

We define a canonical “who signs what” map and verification rules for TrackOne’s control-plane and evidence-plane artifacts. TrackOne distinguishes:

- **Identity/authentication signatures** (Ed25519) for provisioning, policies, and ledger headers.
- **Confidentiality/integrity** of telemetry via AEAD (XChaCha20-Poly1305), not signatures.
- **Public anchoring** via OTS/TSA as an external timestamp proof (not a signature by TrackOne actors).

### Actors and keys

- **Pod identity key**: Ed25519 signing key held by the pod (`sk_pod_ed25519`); its verification key (`pk_pod_ed25519`) is stored in the registry/provisioning record.
- **Gateway identity key**: Ed25519 signing key held by the gateway (`sk_gw_ed25519`); its verification key (`pk_gw_ed25519`) is distributed by operator policy and/or a manufacturer-signed gateway credential.
- **Manufacturer/registry key**: offline signing key used to mint device “birth certificates” (Provisioning Records) and firmware manifests; gateways and auditors verify with the corresponding public key.
- **Peer attestation keys (optional)**: Ed25519 keys used by independent peers to co-sign day roots (ADR-015).

Baseline vs. industrial distribution:

- **Baseline**: `pk_gw_ed25519` is pinned in provisioning tools or operator configuration; pods are not required to store manufacturer keys.
- **Industrial / chain-of-trust**: gateways have manufacturer-issued credentials and verifiers can validate issuer signatures for device/gateway credentials (ADR-019).

### Canonical bytes rule (what is signed)

To avoid “same fields, different bytes” failures:

- All signed artifacts MUST define their signed bytes using a canonical encoding.
- Required: **TrackOne Canonical CBOR** for signed bytes (ADR-034).
- JSON encodings are NOT permitted for signed bytes unless a future ADR explicitly updates ADR-034 and this ADR; verifiers MUST treat JSON encodings as invalid until then.
- Each artifact schema MUST declare the canonicalization algorithm identifier (e.g., `trackone-canonical-cbor-v1`) so verifiers never guess.

Each signed payload MUST include an explicit `type` (domain separation) and `schema_version` so signatures cannot be replayed across artifact kinds.

## Signature map (who signs what, who verifies)

The table below is normative for signers/verifiers. “Requirement” is expressed as: `Required`, `Optional`, or `Required (when ...)` to avoid ambiguous conditional “Yes”.

| Artifact                                    | Purpose                                                                                      | Signer                   | Verified by                       | Requirement                                                   |
| ------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------ | --------------------------------- | ------------------------------------------------------------- |
| **Provisioning Record (Birth Certificate)** | Bind device identity keys + device metadata to an issuer                                     | Manufacturer/Registry    | Gateway, Auditor (optionally Pod) | Required (chain-of-trust deployments; ADR-019)                |
| **Provisioning Session Transcript**         | Bind negotiated suite + KEX public values to the pod identity                                | Pod                      | Gateway                           | Required                                                      |
| **Provisioning Offer (Gateway Hello)**      | Let pod authenticate the gateway and the negotiated session parameters before accepting them | Gateway                  | Pod                               | Optional (recommended when pods can verify `pk_gw_ed25519`)   |
| **Provisioning Ack / Counter-signature**    | Provide non-repudiation that the gateway accepted the exact transcript                       | Gateway                  | Auditor / Pod                     | Optional                                                      |
| **Signed Policy Update**                    | Authorize control-plane policy (cadence, thresholds, feature gates)                          | Gateway or Operator Key  | Pod, Auditor                      | Optional/Deployment-dependent (ADR-025)                       |
| **Firmware Manifest / Release Record**      | Authorize OTA firmware image + hash + version                                                | Manufacturer/Release Key | Pod, Auditor                      | Optional/Deployment-dependent (ADR-026)                       |
| **Block Header / Day Record Signature**     | Evidence-plane integrity: bind Merkle root/day root to gateway identity                      | Gateway                  | Auditor (and verifiers)           | Required (when operator identity/non-repudiation is in scope) |
| **Peer Attestation (day_root)**             | Independent co-signature over day root for fast provenance                                   | Peer(s)                  | Auditor                           | Optional (ADR-015)                                            |

## Provisioning: recommended signature flows

Provisioning signatures are about *control-plane authenticity and downgrade resistance*. Telemetry keys derived from provisioning are then used for AEAD frames; frames are not signed.

### Flow A (minimum): pod-signed transcript (current baseline)

1. Pod and gateway exchange KEX public values (X25519 ephemerals; optional PQ material per ADR-036).
1. Pod constructs the **Provisioning Session Transcript** and signs it with `sk_pod_ed25519`.
1. Gateway verifies the signature using `pk_pod_ed25519` from the registry (or the manufacturer-signed Provisioning Record).
1. Both sides derive channel keys from the agreed KEX outputs, using transcript binding (`th`) where applicable (ADR-036).

This is sufficient when the pod does not authenticate a specific gateway identity (e.g., provisioning is performed in a trusted physical procedure).

### Flow B (mutual): gateway offer + pod transcript (recommended when feasible)

When pods can authenticate the gateway (pinned `pk_gw_ed25519` or manufacturer-issued gateway credential):

1. Gateway sends a **Provisioning Offer** signed with `sk_gw_ed25519`, covering: `device_id`, `kex_suite`, `Ng`, `eG_pub`, and any PQ parameters (e.g., `pq_param_id`, `pk_pq` for gateway-ephemeral PQ).
1. Pod verifies the offer signature with `pk_gw_ed25519` and enforces local policy (e.g., reject downgraded suites).
1. Pod replies with the **Provisioning Session Transcript**, signed with `sk_pod_ed25519`, covering all KEX public values from both sides (see below).
1. Gateway verifies the pod signature, then derives keys.

Optional: gateway emits a **Provisioning Ack** (counter-signature) over the transcript hash `th` to provide non-repudiation for audits.

## Provisioning transcript: minimum required fields

The pod-signed Provisioning Session Transcript MUST cover (canonical bytes):

- `type = "trackone/provisioning_transcript"`
- `schema_version`
- `pod_id` (canonical name)
- `kex_suite`
- `Ng`, `Np`, `T_pod`, `B` (salt inputs)
- `eG_pub`, `eP_pub` (X25519 ephemeral public keys)
- Hybrid/PQ fields when `kex_suite = x25519+mlkem` (ADR-036):
  - `pq_param_id`
  - `ct_kem`
  - `pk_pq` when using a gateway-ephemeral PQ model and the gateway-signed Provisioning Offer included `pk_pq`
    The transcript MUST NOT include any derived secrets (`ss_ecdh`, `ss_kem`, `CK_up`, `CK_down`) and MUST NOT include the Ed25519 signature bytes inside the signed payload (signature is stored as a separate envelope field).

## Verification rules (normative)

### Gateway

- MUST verify the manufacturer/registry signature on a Provisioning Record before trusting `pk_pod_ed25519` or any long-term public keys carried in that record (when ADR-019 chain-of-trust is in use).
- MUST verify the pod signature on the Provisioning Session Transcript before deriving or persisting channel keys.
- MUST enforce suite policy (no opportunistic downgrade) and strict field validation before expensive operations (length checks, supported `pq_param_id`, rate limiting; see ADR-036).

### Pod

- MUST verify any gateway-signed Provisioning Offer or policy update before applying it (when those features are enabled).
- MUST treat unverifiable offers/updates as invalid (no silent fallback to weaker modes).
- Pods are NOT required to verify manufacturer/registry signatures in the baseline (smallest pods may not store issuer public keys). If a pod does verify issuer signatures, it is an optional hardening feature and must be explicitly provisioned with the issuer verification key.

### Auditor / verifier

- Verifies evidence-plane signatures (gateway block headers/day records, optional peer signatures) and anchoring proofs (OTS/TSA) independently of gateway operator trust.
- When chain-of-trust is in scope, verifies manufacturer signatures on Provisioning Records and firmware manifests to relate telemetry to approved devices/firmware.

## Evidence-plane signature coverage

When enabled, a gateway evidence-plane signature MUST cover canonical bytes of the signed object and MUST bind at least:

- the `day_root` (or `merkle_root` for a batch header),
- the site/day identifiers,
- and the digest of the anchored artifact (e.g., `SHA-256(day.bin)`), either embedded directly or referenced via a signed manifest.

This prevents “under-signing” where a signature covers only a root string but not the artifact it is claimed to represent.

## Consequences

### Positive

- Removes ambiguity in signature responsibilities and verification ordering.
- Makes downgrade resistance enforceable by explicit transcript field coverage.
- Provides a clean on-ramp for mutual authentication (without forcing it on the smallest pods).

### Trade-offs

- Mutual authentication requires a deployment story for distributing `pk_gw_ed25519` to pods (pinned key or manufacturer-issued credential).
- Canonical encoding requirements must be implemented consistently across Python and Rust toolchains.

## Acceptance criteria

- ADR-036 references ADR-037 for transcript signature roles.
- Artifact schemas (Provisioning Record, Provisioning Transcript, Policy Update) explicitly define canonical signed bytes and envelope fields.
- Test vectors exist for signature verification on representative artifacts, including at minimum: tampered `kex_suite`, tampered `ct_kem`, wrong `type`, wrong signer key, and non-canonical encoding rejection.
