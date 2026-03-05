# ADR-025: Adaptive Uplink Cadence via Authenticated LoRa Downlink Policy

**Status**: Accepted
**Date**: 2025-12-15
**Updated**: 2026-03-05

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Core cryptographic primitives (Ed25519, HKDF, XChaCha20-Poly1305)
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Telemetry framing and replay policy (uplink framing, `cfg_ack`, device table)
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Canonicalization and Merkle/OTS anchoring (ledger facts)
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy (RNG usage)
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Gateway chain of trust (authentication/verification)
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger (ledger semantics)
- [ADR-026](ADR-026-ota-firmware-updates-over-lora.md): OTA firmware updates over LoRa (shares downlink infrastructure)
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): EnvFact schema and duty-cycled day.cbor anchoring (duty cycle interaction)
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Transport vs. commitment encodings (canonical CBOR for signed/anchored bytes)

## Context

- TrackOne already defines:
  - cryptographic primitives and signatures (ADR-001),
  - replay-safe uplink framing and gateway device state (ADR-002, ADR-024),
  - canonical, auditable ledger artifacts (ADR-003, ADR-019, ADR-024),
  - a low-duty-cycle pod operating model with short RX windows after uplinks (ADR-030).
- TrackOne pods operate over constrained LPWAN links such as LoRa:
  - downlink airtime is scarce,
  - pods are usually Class A-like rather than continuously listening,
  - many pods are battery powered and may deep-sleep between uplinks.
- Fixed uplink cadence is operationally poor:
  - it wastes battery and airtime in quiet conditions,
  - it delays richer observation when local or external risk rises,
  - it forces one conservative cadence across unlike deployments.
- Operators want to adjust cadence using:
  - external hazard signals,
  - device health and battery state,
  - network congestion and duty-cycle conditions.
- Three constraints must remain explicit:
  - Control decisions can only reach a pod during a later RX window. A gateway cannot force an immediate reaction before the pod's next uplink.
  - Not all pods have a trustworthy wall clock while sleeping or after reboot, so absolute Unix-time activation is a poor control primitive.
  - The control plane must bind to the canonical pod identity used by the TrackOne ledger, even if some transports still use a compact local alias for routing.

We need a minimally sufficient adaptive cadence mechanism that remains replay-safe, auditable, and implementable on Class A-style LoRa links without expanding into full LoRaWAN MAC behavior or OTA firmware scope.

## Decision

We adopt an **adaptive uplink cadence policy** carried over authenticated LoRa downlink, with:

- a per-pod monotonic `policy_epoch`,
- a canonical policy object with deterministic bytes,
- receipt-relative activation and expiry semantics,
- explicit distinction between `policy_issued` and `policy_applied`,
- authenticated pod confirmation of the epoch actually in effect.

### 1. Policy identity and epochs

- `policy_epoch` is a monotonically increasing unsigned integer **per pod**.
- Controllers may compute the same cadence parameters for many pods, but each pod receives its own policy object bound to its own target identity and epoch.
- The gateway/controller persists the latest issued epoch for each pod.
- The pod persists the latest accepted policy and active epoch in non-volatile storage.
- Pods reject any policy update whose `policy_epoch` is less than or equal to the locally stored epoch.

Rationale:

- Treating epochs as per-pod avoids ambiguity when a "fleet policy" is delivered opportunistically over separate RX windows.
- Equal-epoch replacement is not allowed; any material policy change requires a new epoch.

### 2. Normative policy object

The normative cadence artifact is the logical object below. Its commitment and signature bytes are the TrackOne canonical CBOR encoding of these fields, per ADR-034.

- `type: "trackone/cadence_policy"`
- `schema_version: u16`
- `target_pod_id: bytes[8]`
  - Canonical TrackOne pod identity.
  - If a deployment still routes LoRa frames using a local `dev_id` alias, that alias is not the normative signed identity and MUST resolve unambiguously to the same `target_pod_id`.
- `policy_epoch: u32`
- `base_period_s: u32`
  - Baseline telemetry period while the policy is active.
- `jitter_pct: u8`
  - Bounded randomization, typically 0-25%, to avoid herd synchronization.
- `burst_profile: enum`
  - `Normal`
  - `BurstOnEvent`
  - `HighFrequencyWindow`
- `burst_count: u8`
  - Number of extra event-driven uplinks permitted when `burst_profile = BurstOnEvent`.
  - `0` means "implementation default disabled".
- `hf_period_s: u32`
  - Temporary faster period used only when `burst_profile = HighFrequencyWindow`.
  - `0` means unused.
- `hf_window_s: u32`
  - Duration, relative to activation, for which `hf_period_s` applies.
  - `0` means unused.
- `activate_delay_s: u32`
  - Delay relative to verified receipt on the pod.
  - `0` means immediate activation.
- `policy_ttl_s: u32`
  - Lifetime relative to activation.
  - `0` means "until superseded by a newer epoch".
- `flags: u16`
  - Reserved for future bounded extensions.

Validation rules:

- `base_period_s` MUST be non-zero.
- `jitter_pct` MUST be bounded by deployment policy; recommended maximum is 25.
- `burst_count`, `hf_period_s`, and `hf_window_s` MUST be zero when their corresponding profile is not active.
- `hf_period_s` MUST be non-zero and strictly less than or equal to `base_period_s` when `burst_profile = HighFrequencyWindow`.
- Gateways and pods MUST reject policies that would violate deployment battery or airtime guardrails.

### 3. Authentication, transport, and replay resistance

- Downlink policy messages are scheduled only in Class A-style RX windows after uplinks.
- The authenticated policy payload is the canonical CBOR byte string of the `CadencePolicy` object above.
- Deployments MUST provide authenticity, integrity, and replay resistance using one of these mechanisms:
  - an Ed25519 signature over the canonical policy bytes, verified against a provisioned policy signer key; or
  - a device-specific AEAD envelope carrying the canonical policy bytes.
- If AEAD downlink is used:
  - the downlink key MUST be distinct from the uplink key; refer to it as `ck_down`,
  - reusing `ck_up` for downlink protection is forbidden,
  - the gateway device table is extended with `ck_down` or equivalent derivation inputs,
  - the downlink nonce/sequence space MUST be independent of uplink frame counters.
- If signatures are used:
  - the signature MUST cover the canonical CBOR bytes only,
  - the policy signer is a control-plane authority, not a transport shortcut,
  - transport-specific packed/TLV framing is allowed only as an envelope around the canonical policy bytes and optional signature.
- Replay/rollback resistance is achieved by the combination of:
  - target identity binding,
  - `policy_epoch`,
  - authenticated transport or signature verification,
  - pod-side rejection of stale or duplicate epochs.

### 4. Gateway-side policy computation, latency, and ledger facts

- Gateways or upstream controllers compute cadence policies from inputs such as:
  - external hazard feeds,
  - network telemetry,
  - pod battery and health state,
  - historical patterns in the TrackOne ledger.
- The scoring or heuristic algorithm remains out of scope for this ADR.
- The gateway MUST treat control-plane latency honestly:
  - a new policy can only take effect after the pod's next uplink opens an RX window,
  - deployments that require faster response MUST use a shorter baseline heartbeat, pod-local escalation heuristics, or a different radio mode,
  - this ADR does not claim real-time hazard fan-out to sleeping Class A pods.
- The gateway logs:
  - the canonical policy object,
  - its policy digest (`SHA-256` of canonical policy bytes),
  - the resulting transport envelope or signature material,
  - delivery attempts and failures.

Ledger facts are split as follows:

- `policy_issued`
  - emitted when a new canonical policy object is minted for a pod and queued or transmitted,
  - records at least `target_pod_id`, `policy_epoch`, policy digest, issuer identity, and issuance time.
- `policy_applied`
  - emitted only after authenticated pod confirmation that the epoch is active,
  - records at least `target_pod_id`, `policy_epoch`, policy digest, pod-confirmed active time or receipt-relative status, and gateway observation time.

A gateway MUST NOT claim that a policy was applied merely because it was issued or because a downlink was attempted.

### 5. Pod behavior and acknowledgement

- On boot, the pod loads:
  - the persisted active policy and epoch, if any,
  - otherwise a safe deployment default:
    - baseline `base_period_s`,
    - modest jitter,
    - `burst_profile = Normal`.
- On receiving a downlink policy update during an RX window, the pod MUST:
  - verify the transport/authentication mechanism,
  - reconstruct and validate the canonical policy bytes,
  - verify that `target_pod_id` matches the local provisioned identity,
  - reject the message if `policy_epoch <= current_epoch`,
  - persist the candidate policy and its digest if valid.
- Activation is relative to receipt:
  - if `activate_delay_s = 0`, activate immediately,
  - otherwise schedule activation after `activate_delay_s` based on local monotonic uptime or sleep timer semantics,
  - no trusted wall clock is required.
- Expiry is also relative:
  - if `policy_ttl_s = 0`, the policy remains active until superseded,
  - otherwise the pod reverts to the safe default cadence after `policy_ttl_s` has elapsed from activation.
- While active, the pod applies:
  - `base_period_s + jitter` for `Normal`,
  - `base_period_s + jitter` plus up to `burst_count` extra transmissions for local events in `BurstOnEvent`,
  - `hf_period_s + jitter` for `hf_window_s` after activation, then `base_period_s + jitter` for the remainder of the active policy in `HighFrequencyWindow`.

Authenticated confirmation is mandatory:

- The pod MUST confirm the accepted policy on the next feasible authenticated uplink using `cfg_ack` or an equivalent authenticated control-status field.
- The confirmation MUST include at least:
  - `target_pod_id` or unambiguous local alias,
  - `policy_epoch`,
  - `policy_digest`,
  - `status`.
- Minimum statuses:
  - `stored`
  - `applied`
  - `rejected`
  - `expired`
- The gateway writes `policy_applied` only after receiving authenticated confirmation that resolves to `status = applied`, or after a later authenticated telemetry/control uplink that explicitly reports the active epoch and matching digest.

### 6. Scope and non-goals

In scope:

- Authenticated downlink control of telemetry cadence.
- Per-pod policy epochs and replay/rollback protection.
- Canonical policy bytes for signatures, digests, and ledger facts.
- Authenticated pod confirmation of applied policy state.

Out of scope:

- Firmware or bootloader updates, handled by ADR-026.
- Full LoRaWAN MAC behavior beyond the simplified Class A-style model.
- Absolute wall-clock scheduling of future policies on pods without a trusted clock.
- Application configuration unrelated to uplink cadence.

## Consequences

### Positive

- **Auditable state transitions**:
  - The ledger now distinguishes `policy_issued` from `policy_applied`.
  - Verifiers can tell the difference between operator intent and pod-confirmed reality.
- **No hidden clock dependency**:
  - Pods activate and expire policies using receipt-relative timers rather than unsupported Unix-time assumptions.
- **Deterministic control artifacts**:
  - Signatures, digests, and ledger references all point at the same canonical policy bytes.
- **Bounded operational claims**:
  - The ADR now states the real latency limit of Class A-style policy delivery.
- **Separation of concerns**:
  - Cadence control remains separate from OTA firmware delivery, though both may share downlink infrastructure.

### Negative

- **More device and gateway state**:
  - Pods must persist policy digest, epoch, and activation state.
  - Gateways must track issued-vs-applied facts and confirmation status.
- **Additional control traffic**:
  - `cfg_ack` or equivalent status reporting consumes scarce uplink bytes.
- **Downlink keying complexity**:
  - AEAD-based downlinks require an explicit `ck_down` story instead of informally reusing uplink state.
- **Latency remains bounded by uplink opportunity**:
  - Hazard-driven policy changes are only as fast as the next uplink/RX window.

## Alternatives considered

- **Fixed cadence configured only at provisioning time**
  - Simpler, no control channel required.
  - Rejected because it cannot respond to changing risk or network conditions.
- **Pod-local adaptation only, with no downlink policy**
  - Saves downlink airtime.
  - Rejected because operators cannot coordinate fleet behavior or audit externally driven changes.
- **Absolute Unix-time `valid_from` / `valid_until` fields**
  - Attractive for centrally scheduled campaigns.
  - Rejected for this ADR because many duty-cycled pods lack a trustworthy wall clock during sleep, reboot, or RTC loss.
- **Full LoRaWAN ADR / FUOTA-style dependence**
  - Useful in some ecosystems.
  - Rejected here because TrackOne needs explicit cadence semantics and ledger-visible control facts independent of a specific LoRaWAN stack.
- **Out-of-band reconfiguration only**
  - No downlink control channel.
  - Rejected because it does not scale to remote, battery-powered deployments.

## Testing and migration

### Testing

- Gateway-side tests:
  - canonical CBOR stability for `CadencePolicy`,
  - signature verification and AEAD unwrap for downlink policy envelopes,
  - rejection of stale/duplicate epochs,
  - correct emission of `policy_issued` vs. `policy_applied`,
  - handling of missed RX windows and retried delivery attempts.
- Pod-side tests:
  - persistence across reboot,
  - receipt-relative activation and expiry,
  - profile-specific scheduling (`Normal`, `BurstOnEvent`, `HighFrequencyWindow`),
  - authenticated `cfg_ack` generation with matching policy digest,
  - rejection of wrong target identity, wrong signer, wrong digest, stale epoch, and malformed canonical bytes.
- Hardware-in-the-loop tests:
  - loss and delayed RX windows,
  - battery guardrail rejection,
  - confirmation arriving much later than issuance,
  - fallback to safe defaults after expiry or reboot.

### Migration

- Existing deployments without adaptive cadence remain on safe default policy behavior with `policy_epoch = 0`.
- Rollout sequence:
  - provision or derive `ck_down` where AEAD downlink is used, or provision the policy signer key where signatures are used,
  - enable `cfg_ack` or equivalent authenticated control-status uplinks,
  - start issuing `policy_epoch = 1` to pilot pods,
  - promote to broader fleets once `policy_issued` and `policy_applied` facts remain consistent in the ledger.
- Draft-era fields `valid_from_unix_s` and `valid_until_unix_s` are superseded by `activate_delay_s` and `policy_ttl_s`.
  - Immediate policies map to `activate_delay_s = 0`.
  - Indefinite policies map to `policy_ttl_s = 0`.
  - Absolute future scheduling on sleeping pods remains out of scope unless a later ADR introduces a trusted time model.
