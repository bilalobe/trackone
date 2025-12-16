# ADR-025: Adaptive Uplink Cadence via Authenticated LoRa Downlink Policy

**Status**: Proposed (Near-term, LoRa M#1)
**Date**: 2025-12-15
**Related ADRs**:

- ADR-001: Core cryptographic primitives (Ed25519, HKDF, XChaCha20-Poly1305)
- ADR-002: Telemetry framing and replay policy (pod uplink model)
- ADR-018: Cryptographic randomness and nonce policy (RNG usage)
- ADR-019: Gateway chain of trust (authentication/verification)
- ADR-024: Anti-replay and OTS-backed ledger (policy-change facts)
- ADR-026: OTA firmware updates over LoRa (uses same downlink infrastructure)
- ADR-030: EnvFact schema and duty-cycled day.bin anchoring (duty cycle interaction)

# Decision

We need a minimally sufficient adaptive uplink policy mechanism using authenticated downlink control messages over LoRa, without committing to a full LoRaWAN stack or OTA firmware scope (which is handled separately in ADR-026).

- Clear auditability of policy changes through the TrackOne ledger (ADR-003, ADR-024, ADR-019).
- Replay safety (ADR-002, ADR-024).
- End-to-end cryptographic guarantees (ADR-001, ADR-018).
- We must preserve:
  - Downlink capacity is scarce; control messages must be compact and infrequent.
  - Devices will mostly behave like Class A: open short RX windows after each uplink; no continuous listening.
- LoRa-like constraints apply even if we are not strictly implementing full LoRaWAN:
  - Network conditions (channel utilization, duty cycle limits).
  - Observed device behavior (signal quality, battery state, anomaly scores).
  - Environmental risk indicators (e.g., weather alerts, flood/wildfire risk).
- Operators want to dynamically adjust uplink frequency based on:
  - They can under-sample or saturate the network during high-risk, rapidly changing conditions if not dimensioned conservatively.
  - They over-sample during low-risk, stable conditions.
- Fixed uplink periods are wasteful:
- TrackOne devices are expected to operate over constrained LPWAN links such as LoRa, often battery-powered and deployed in harsh environments.
  - ADR-024 extends anti-replay policy and introduces an OTS-backed ledger for telemetry.
  - ADR-019 defines the Rust gateway chain of trust for the stationary calendar and upstream verification pipeline.
  - ADR-003 defines canonicalization and Merkle + OpenTimestamps anchoring.
  - ADR-002 defines the telemetry framing, nonce/replay policy, and gateway device table.
  - ADR-001 defines the core cryptographic primitives (X25519, HKDF, XChaCha20-Poly1305, Ed25519, SHA-256).
- TrackOne today focuses on secure, replay-safe telemetry ingestion and verifiable storage:

## Context

**Date**: 2025-12-15
**Status**: Proposed (Near-term, LoRa M#1)

# ADR-025: Adaptive Uplink Cadence via Authenticated LoRa Downlink Policy

- No schema-breaking changes are required for the TrackOne ledger; policy changes are represented as additional canonical facts linked to devices and time ranges.
  - Monitor ledger entries and telemetry cadence for anomalies.
  - Start issuing `policy_epoch = 1` policies to pilot fleets.
- Once device and gateway support is verified:
  - Gradually roll out policy support with feature flags on the gateway.
  - Default to a safe baseline policy (`policy_epoch = 0`).
- Existing deployments without adaptive cadence:
- **Migration**:
  - Policy rollback attempts and replays.
  - Missed RX windows and retry behavior.
  - Hardware-in-the-loop tests with a gateway simulator to test:
    - Burst profiles and jittered send schedules.
    - Correct handling of `policy_epoch` and `valid_from`/`valid_until`.
    - Policy storage and recovery across reboots.
  - Unit and integration tests for:
- **Device-side testing**:
  - Logging and ledger emission of policy-change facts (ADR-003, ADR-024, ADR-019).
  - Policy computation based on synthetic risk inputs.
  - Integration tests for:
    - Epoch and replay/rollback rules.
    - Signature/AEAD wrapping and unwrapping (ADR-001, ADR-018).
    - Policy object construction and validation.
  - Unit tests for:
- **Gateway-side testing**:

## Testing & Migration

- Rejected since it does not scale for distributed, remote deployments and undermines automated risk response.
- No downlink control channel.
- **Out-of-band re-provisioning (USB/JTAG/local Wi-Fi)**:
  - We may later integrate with LoRaWAN ADR but still want an explicit, audited cadence policy concept.
    - Does not directly express application cadence semantics (risk/weather-based telemetry timing).
    - Locks us into a specific stack and server implementation.
  - Partially overlaps with our needs but:
  - Use existing LoRaWAN mechanisms for rate and power control.
- **Full LoRaWAN MAC with network server–driven ADR (Adaptive Data Rate)**:
  - Rejected because operators cannot coordinate fleet-level behavior or respond to external risk feeds; also harder to audit.
  - Devices self-adjust cadence based solely on local sensors and heuristics.
- **Application-level adaptive logic only (no downlink control)**:
  - Rejected because it cannot respond to evolving risk and network conditions, leading to poor battery and spectrum utilization.
  - Simpler, no control channel required.
- **Fixed uplink intervals configured at provisioning time only**:

## Alternatives Considered

- Gateway logic must tolerate and retry missed updates idempotently.
- If devices miss multiple RX windows (e.g., due to RF issues), policy updates may be delayed.
- **Dependency on reliable RX windows**:
  - Overly conservative policies may reduce situational awareness in high-risk scenarios.
  - Aggressive high-frequency policies could exhaust device batteries or violate duty cycle limits.
- **Risk of misconfiguration**:
  - Devices must implement policy storage, validation, and local state machines for burst profiles.
  - Gateways must track policy epochs, compute cadence, and schedule downlink updates.
- **Increased complexity in gateway and device logic**:

### Negative

- Cadence control is decoupled from firmware updates and more invasive maintenance flows (ADR-026 can build on this).
- **Separation of concerns**:
  - Designed to fit within tight downlink budgets for LoRa Class A-style deployments.
- **Small, infrequent control messages**:
  - Every accepted policy change is attributable, timestamped, and anchored via the TrackOne ledger (ADR-003, ADR-024, ADR-019).
  - `policy_epoch` prevents rollback attacks and stale policies.
- **Replay-safe, auditable policy changes**:
  - Gateways can temporarily increase sampling under high-risk conditions without long-term reconfiguration.
  - Devices spend minimal airtime in low-risk scenarios, extending battery life and reducing network load.
- **Adaptive efficiency**:

### Positive

## Consequences

- Application-level configuration that is not directly related to uplink timing.
- Full LoRaWAN MAC/stack behavior beyond the simplified Class A-style assumption.
- Device key provisioning beyond references to ADR-001/018/019.
- Firmware or bootloader updates (handled by ADR-026).
- Explicitly out of scope for this ADR:
  - Policy epoching, replay/rollback protection, and ledger visibility for policy changes.
  - Uplink timing and burst profile control via authenticated downlink policies.
- In scope:

### Scope and Non-Goals

- Respect `valid_until_unix_s`; on expiration, revert to safe default cadence until a new policy is received.
- Apply `burst_profile` logic locally (e.g., temporary high-frequency sending after an internal event).
- Derive actual send times from `base_period_s` + jitter.
- While running:
  - If `new_epoch > current_epoch`: accept, persist, and take effect at `valid_from_unix_s` or immediately.
  - If `new_epoch <= current_epoch`: discard and log locally for diagnostics.
  - Check `policy_epoch`:
  - Verify authenticity (signature/AEAD) and integrity.
- On receiving a policy update in an RX window:
  - `burst_profile` = `Normal`.
  - `jitter_pct` = small default (e.g., 10%).
  - E.g., `base_period_s` = configured baseline for the deployment profile.
  - If no policy is present, uses a **safe default**:
  - Loads its persisted `policy_epoch` and latest policy.
- On boot, the device:

### Device Behavior

- A policy is rolled back or overridden.
- A new `policy_epoch` is issued for a device or group.
- Gateways write a **policy-change fact** into the TrackOne ledger (ADR-003, ADR-024, ADR-019) whenever:
  - The resulting signed/AEAD-wrapped control messages.
  - The proposed policy objects.
- Gateways log:
  - The computation strategy (e.g., heuristic vs. ML-based risk scoring) is out of scope for this ADR and can evolve independently.
    - Historical patterns from the TrackOne ledger (ADR-024).
    - Device state (battery levels, internal alerts).
    - Network telemetry (packet loss, RSSI/SNR, duty cycle utilization).
    - External risk feeds (e.g., weather APIs, hazard indices).
  - Inputs may include:
- Gateways (and/or upstream controllers) are responsible for computing cadence policies.

### Gateway-Side Policy Computation

- No continuous listening or Class C-like behavior is required; energy remains bounded.
- The gateway schedules policy updates in these RX windows.
- The device opens one or more short RX windows after each uplink.
- Downlink messages are scheduled **only in Class A-style RX windows**:
  - Be replay-resistant, by using `policy_epoch` and an AEAD nonce/sequence approach coherent with ADR-002 and ADR-024.
  - Bind the policy to a specific device or device group.
  - The chosen concrete mechanism must:
    - An Ed25519-signed policy object verified with a provisioned device trust anchor.
    - A key derivation and AEAD scheme consistent with ADR-001 and ADR-018 (e.g., X25519 + HKDF + XChaCha20-Poly1305), or
  - The message is authenticated using:
    - Cadence parameters listed above.
    - `policy_epoch`.
    - Device identifier (as per ADR-002).
  - The control message payload includes at least:
- Each policy update is sent as a **small, authenticated control message** over LoRa:

### Authenticated Downlink Control Messages

- `flags: u16` — reserved bitfield for future extension (e.g., battery-aware adjustments, priority channels).
- `valid_until_unix_s: u32` — optional soft expiry for policy; upon expiry, device falls back to a safe baseline period.
- `valid_from_unix_s: u32` — optional start time to apply policy (0 = immediate).
- `hf_window_s: u32` — optional duration for high-frequency profile (seconds, 0 = disabled).
  - `HighFrequencyWindow`: shorter period for a limited time window (see below).
  - `BurstOnEvent`: N quick uplinks when a local event triggers, then revert to `Normal`.
  - `Normal`: single uplink per period.
- `burst_profile: enum` — one of:
- `jitter_pct: u8` — bounded randomization (e.g., 0–25%) to avoid synchronization.
- `base_period_s: u32` — nominal telemetry period, in seconds.
- `policy_epoch: u32`
- Define a **Cadence Policy** structure (logical model; wire format can be CBOR/TLV/packed struct):
  - Equal to the locally stored epoch but with a mismatched signature or payload.
  - Less than the locally stored epoch (replay/rollback protection).
  - Devices reject any downlink policy update whose `policy_epoch` is:
    - Persisted on the device in non-volatile storage.
    - Persisted in the gateway’s device table (ADR-002) and the TrackOne ledger (ADR-003, ADR-024).
    - Assigned and updated by the gateway/controller.
  - `policy_epoch` is:
- Define a **`policy_epoch`** as a monotonically increasing unsigned integer per device.

### Policy Object and Epoch

We introduce an **adaptive uplink cadence policy** driven by authenticated, compact downlink policy updates. The scope is limited to configuring uplink timing and burst patterns; firmware update, app-level configuration, and key management remain out of scope for this ADR.
