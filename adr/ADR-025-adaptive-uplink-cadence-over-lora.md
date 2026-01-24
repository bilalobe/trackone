# ADR-025: Adaptive Uplink Cadence via Authenticated LoRa Downlink Policy

**Status**: Proposed
**Date**: 2025-12-15

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Core cryptographic primitives (Ed25519, HKDF, XChaCha20-Poly1305)
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Telemetry framing and replay policy (pod uplink model)
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy (RNG usage)
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Gateway chain of trust (authentication/verification)
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger (policy-change facts)
- [ADR-026](ADR-026-ota-firmware-updates-over-lora.md): OTA firmware updates over LoRa (uses same downlink infrastructure)
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): EnvFact schema and duty-cycled day.bin anchoring (duty cycle interaction)

## Context

- TrackOne today focuses on secure, replay-safe telemetry ingestion and verifiable storage:
  - ADR-001 defines the core cryptographic primitives (X25519, HKDF, XChaCha20-Poly1305, Ed25519, SHA-256).
  - ADR-002 defines the telemetry framing, nonce/replay policy, and gateway device table.
  - ADR-003 defines canonicalization and Merkle + OpenTimestamps anchoring.
  - ADR-019 defines the Rust gateway chain of trust for the stationary calendar and upstream verification pipeline.
  - ADR-024 extends anti-replay policy and introduces an OTS-backed ledger for telemetry.
- TrackOne devices are expected to operate over constrained LPWAN links such as LoRa, often battery-powered and deployed in harsh environments.
- Fixed uplink periods are wasteful:
  - They over-sample during low-risk, stable conditions.
  - They can under-sample or saturate the network during high-risk, rapidly changing conditions if not dimensioned conservatively.
- Operators want to dynamically adjust uplink frequency based on:
  - Environmental risk indicators (e.g., weather alerts, flood/wildfire risk).
  - Observed device behavior (signal quality, battery state, anomaly scores).
  - Network conditions (channel utilization, duty cycle limits).
- LoRa-like constraints apply even if we are not strictly implementing full LoRaWAN:
  - Devices will mostly behave like Class A: open short RX windows after each uplink; no continuous listening.
  - Downlink capacity is scarce; control messages must be compact and infrequent.
- We must preserve:
  - End-to-end cryptographic guarantees (ADR-001, ADR-018).
  - Replay safety (ADR-002, ADR-024).
  - Clear auditability of policy changes through the TrackOne ledger (ADR-003, ADR-024, ADR-019).

We need a minimally sufficient adaptive uplink policy mechanism using authenticated downlink control messages over LoRa, without committing to a full LoRaWAN stack or OTA firmware scope (which is handled separately in ADR-026).

## Decision

We introduce an **adaptive uplink cadence policy** driven by authenticated, compact downlink policy updates. The scope is limited to configuring uplink timing and burst patterns; firmware update, app-level configuration, and key management remain out of scope for this ADR.

### Policy Object and Epoch

- Define a **`policy_epoch`** as a monotonically increasing unsigned integer per device.
  - `policy_epoch` is:
    - Assigned and updated by the gateway/controller.
    - Persisted in the gateway's device table (ADR-002) and the TrackOne ledger (ADR-003, ADR-024).
    - Persisted on the device in non-volatile storage.
  - Devices reject any downlink policy update whose `policy_epoch` is:
    - Less than the locally stored epoch (replay/rollback protection).
    - Equal to the locally stored epoch but with a mismatched signature or payload.
- Define a **Cadence Policy** structure (logical model; wire format can be CBOR/TLV/packed struct):
- `policy_epoch: u32`
- `base_period_s: u32` — nominal telemetry period, in seconds.
- `jitter_pct: u8` — bounded randomization (e.g., 0–25%) to avoid synchronization.
- `burst_profile: enum` — one of:
  - `Normal`: single uplink per period.
  - `BurstOnEvent`: N quick uplinks when a local event triggers, then revert to `Normal`.
  - `HighFrequencyWindow`: shorter period for a limited time window (see below).
- `hf_window_s: u32` — optional duration for high-frequency profile (seconds, 0 = disabled).
- `valid_from_unix_s: u32` — optional start time to apply policy (0 = immediate).
- `valid_until_unix_s: u32` — optional soft expiry for policy; upon expiry, device falls back to a safe baseline period.
- `flags: u16` — reserved bitfield for future extension (e.g., battery-aware adjustments, priority channels).

### Authenticated Downlink Control Messages

- Each policy update is sent as a **small, authenticated control message** over LoRa:
  - The control message payload includes at least:
    - Device identifier (as per ADR-002).
    - `policy_epoch`.
    - Cadence parameters listed above.
  - The message is authenticated using:
    - A key derivation and AEAD scheme consistent with ADR-001 and ADR-018 (e.g., X25519 + HKDF + XChaCha20-Poly1305), or
    - An Ed25519-signed policy object verified with a provisioned device trust anchor.
  - The chosen concrete mechanism must:
    - Bind the policy to a specific device or device group.
    - Be replay-resistant, by using `policy_epoch` and an AEAD nonce/sequence approach coherent with ADR-002 and ADR-024.
- Downlink messages are scheduled **only in Class A-style RX windows**:
  - The device opens one or more short RX windows after each uplink.
  - The gateway schedules policy updates in these RX windows.
  - No continuous listening or Class C-like behavior is required; energy remains bounded.

### Gateway-Side Policy Computation

- Gateways (and/or upstream controllers) are responsible for computing cadence policies.
  - Inputs may include:
    - External risk feeds (e.g., weather APIs, hazard indices).
    - Network telemetry (packet loss, RSSI/SNR, duty cycle utilization).
    - Device state (battery levels, internal alerts).
    - Historical patterns from the TrackOne ledger (ADR-024).
  - The computation strategy (e.g., heuristic vs. ML-based risk scoring) is out of scope for this ADR and can evolve independently.
- Gateways log:
  - The proposed policy objects.
  - The resulting signed/AEAD-wrapped control messages.
- Gateways write a **policy-change fact** into the TrackOne ledger (ADR-003, ADR-024, ADR-019) whenever:
  - A new `policy_epoch` is issued for a device or group.
  - A policy is rolled back or overridden.

### Device Behavior

- On boot, the device:
  - Loads its persisted `policy_epoch` and latest policy.
  - If no policy is present, uses a **safe default**:
    - E.g., `base_period_s` = configured baseline for the deployment profile.
    - `jitter_pct` = small default (e.g., 10%).
    - `burst_profile` = `Normal`.
- On receiving a policy update in an RX window:
  - Verify authenticity (signature/AEAD) and integrity.
  - Check `policy_epoch`:
    - If `new_epoch <= current_epoch`: discard and log locally for diagnostics.
    - If `new_epoch > current_epoch`: accept, persist, and take effect at `valid_from_unix_s` or immediately.
- While running:
  - Derive actual send times from `base_period_s` + jitter.
  - Apply `burst_profile` logic locally (e.g., temporary high-frequency sending after an internal event).
  - Respect `valid_until_unix_s`; on expiration, revert to safe default cadence until a new policy is received.

### Scope and Non-Goals

- In scope:
  - Uplink timing and burst profile control via authenticated downlink policies.
  - Policy epoching, replay/rollback protection, and ledger visibility for policy changes.
- Explicitly out of scope for this ADR:
  - Firmware or bootloader updates (handled by ADR-026).
  - Device key provisioning beyond references to ADR-001/018/019.
  - Full LoRaWAN MAC/stack behavior beyond the simplified Class A-style assumption.
  - Application-level configuration that is not directly related to uplink timing.

## Consequences

### Positive

- **Adaptive efficiency**:
  - Devices spend minimal airtime in low-risk scenarios, extending battery life and reducing network load.
  - Gateways can temporarily increase sampling under high-risk conditions without long-term reconfiguration.
- **Replay-safe, auditable policy changes**:
  - `policy_epoch` prevents rollback attacks and stale policies.
  - Every accepted policy change is attributable, timestamped, and anchored via the TrackOne ledger (ADR-003, ADR-024, ADR-019).
- **Small, infrequent control messages**:
  - Designed to fit within tight downlink budgets for LoRa Class A-style deployments.
- **Separation of concerns**:
  - Cadence control is decoupled from firmware updates and more invasive maintenance flows (ADR-026 can build on this).

### Negative

- **Increased complexity in gateway and device logic**:
  - Gateways must track policy epochs, compute cadence, and schedule downlink updates.
  - Devices must implement policy storage, validation, and local state machines for burst profiles.
- **Risk of misconfiguration**:
  - Aggressive high-frequency policies could exhaust device batteries or violate duty cycle limits.
  - Overly conservative policies may reduce situational awareness in high-risk scenarios.
- **Dependency on reliable RX windows**:
  - If devices miss multiple RX windows (e.g., due to RF issues), policy updates may be delayed.
  - Gateway logic must tolerate and retry missed updates idempotently.

## Alternatives Considered

- **Fixed uplink intervals configured at provisioning time only**:
  - Simpler, no control channel required.
  - Rejected because it cannot respond to evolving risk and network conditions, leading to poor battery and spectrum utilization.
- **Application-level adaptive logic only (no downlink control)**:
  - Devices self-adjust cadence based solely on local sensors and heuristics.
  - Rejected because operators cannot coordinate fleet-level behavior or respond to external risk feeds; also harder to audit.
- **Full LoRaWAN MAC with network server–driven ADR (Adaptive Data Rate)**:
  - Use existing LoRaWAN mechanisms for rate and power control.
  - Partially overlaps with our needs but:
    - Locks us into a specific stack and server implementation.
    - Does not directly express application cadence semantics (risk/weather-based telemetry timing).
  - We may later integrate with LoRaWAN ADR but still want an explicit, audited cadence policy concept.
- **Out-of-band re-provisioning (USB/JTAG/local Wi-Fi)**:
  - No downlink control channel.
  - Rejected since it does not scale for distributed, remote deployments and undermines automated risk response.

## Testing & Migration

- **Gateway-side testing**:
  - Unit tests for:
    - Policy object construction and validation.
    - Signature/AEAD wrapping and unwrapping (ADR-001, ADR-018).
    - Epoch and replay/rollback rules.
  - Integration tests for:
    - Policy computation based on synthetic risk inputs.
    - Logging and ledger emission of policy-change facts (ADR-003, ADR-024, ADR-019).
- **Device-side testing**:
  - Unit and integration tests for:
    - Policy storage and recovery across reboots.
    - Correct handling of `policy_epoch` and `valid_from`/`valid_until`.
    - Burst profiles and jittered send schedules.
  - Hardware-in-the-loop tests with a gateway simulator to test:
    - Missed RX windows and retry behavior.
    - Policy rollback attempts and replays.
- **Migration**:
  - Existing deployments without adaptive cadence:
    - Default to a safe baseline policy (`policy_epoch = 0`).
    - Gradually roll out policy support with feature flags on the gateway.
  - Once device and gateway support is verified:
    - Start issuing `policy_epoch = 1` policies to pilot fleets.
    - Monitor ledger entries and telemetry cadence for anomalies.
  - No schema-breaking changes are required for the TrackOne ledger; policy changes are represented as additional canonical facts linked to devices and time ranges.
