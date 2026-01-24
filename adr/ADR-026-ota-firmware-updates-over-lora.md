# ADR-026: Future OTA Firmware Updates over LoRa (Signed, Chunked, Dual-Slot)

**Status**: Proposed (Later milestone, LoRa M#N)
**Date**: 2025-12-15

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Core cryptographic primitives (Ed25519 firmware signatures)
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Telemetry framing and replay policy (device state model)
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and OTS anchoring (manifest canonicalization)
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy (secure RNG for nonces)
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Gateway chain of trust (firmware provenance and verification)
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger (OTA events as facts)
- [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md): Adaptive uplink cadence (downlink infrastructure reuse)
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): EnvFact schema and duty-cycled day.bin anchoring (operational context)

## Context

- TrackOne’s current focus is secure telemetry ingestion and verifiable storage:
  - ADR-001 defines cryptographic primitives, including Ed25519 for firmware/config signatures.
  - ADR-002 defines telemetry framing and anti-replay policies for uplinks.
  - ADR-003 defines canonicalization and Merkle + OpenTimestamps anchoring.
  - ADR-019 defines the Rust gateway chain of trust for the stationary calendar and upstream verification.
  - ADR-024 defines anti-replay policies and an OTS-backed ledger for telemetry and related events.
- Over-the-air (OTA) firmware updates are not required for the initial LoRa milestones, but:
  - Physical access to deployed devices is expensive or impossible for some use cases.
  - Critical security fixes and protocol changes may be required over the device lifetime.
- LoRa and similar LPWANs impose severe constraints:
  - Low data rates, strict duty cycle limits, and very limited downlink capacity.
  - Class A-style devices listen only in short RX windows after uplinks.
  - Firmware images are typically 100s of KiB, requiring many downlink fragments.
- We already plan to introduce authenticated downlink control messages for adaptive uplink cadence (ADR-025).
  - OTA updates must **reuse and extend** that chain of trust, not invent a parallel mechanism.
- Requirements for OTA firmware:
  - Signed firmware manifests with verifiable provenance (ADR-001, ADR-019).
  - Chunked/segmented transfer resilient to loss and intermittent connectivity.
  - Dual-slot or similar bootloader with rollback capability on failure.
  - Operator-controlled and rare (e.g., emergency security fixes, critical feature changes), not routine.

This ADR defines the high-level architecture and constraints for future OTA firmware updates over LoRa, without specifying the exact on-device bootloader implementation, which may be platform-specific.

## Decision

We will support **rare, operator-driven OTA firmware updates over LoRa** using:

- A signed firmware manifest model anchored in the TrackOne chain of trust.
- Chunked firmware transfer using authenticated downlink fragments.
- A dual-slot (A/B) or equivalent bootloader with rollback and integrity checks.
- Explicit separation from adaptive cadence control (ADR-025), with shared cryptographic and ledger primitives.

### Firmware Manifest

- For each firmware release, we define a **Firmware Manifest**, modeled as a canonical JSON (ADR-003) object:
  - `fw_id`: unique identifier (e.g., semantic version + build hash).
  - `target_hardware`: platform identifier(s) (MCU, board revision, radio type).
  - `image_digest`: SHA-256 digest of the full firmware image (ADR-001).
  - `image_size_bytes`: total size of the firmware image.
  - `chunk_size_bytes`: intended maximum chunk size for LoRa transfer.
  - `required_min_fw_id`: minimum currently-running firmware version that can accept this update (to control upgrade paths).
  - `release_channel`: e.g., `stable`, `beta`, `emergency_patch`.
  - `valid_from_unix_s` / `valid_until_unix_s` (optional).
  - `metadata`: optional notes, flags (e.g., `security_fix`, `breaking_change`).
- The manifest is:
  - Canonicalized per ADR-003.
  - Signed with an Ed25519 key rooted in the TrackOne chain of trust (ADR-001, ADR-019).
  - Optionally anchored in the TrackOne ledger (ADR-024) together with:
    - The manifest itself (or its digest).
    - The deployment decision (which fleets/sites it applies to).

### Dual-Slot / Rollback Bootloader

- Devices must implement a **dual-slot (A/B) or equivalent bootloader**:
  - Two firmware slots in flash:
    - `slot_active`: currently running, known-good firmware.
    - `slot_candidate`: target of the OTA update.
  - A small, robust bootloader region that is:
    - Immutable or updated only under tightly controlled conditions.
    - Responsible for selecting which slot to boot, verifying integrity, and performing rollback.
- Boot-time behavior:
  - Verify the integrity of the active slot and, if instructed to switch to the candidate slot:
    - Verify the candidate image digest matches the manifest.
    - Verify the candidate manifest signature against a built-in trust anchor (ADR-001, ADR-019).
  - Only mark the new firmware as “confirmed” after successful boot and basic self-checks.
  - If the new firmware fails to boot or self-check:
    - Roll back to the previously known-good slot.
    - Record an event for later upload via telemetry (e.g., “OTA failure, rolled back to fw_id=X”).

### Chunked Transfer over LoRa

- Firmware image transfer is **chunked into small fragments** suitable for LoRa downlink:
  - Chunk size is determined by:
    - `chunk_size_bytes` in the manifest.
    - Local regulatory and radio constraints (duty cycle, maximum payload).
  - Each chunk is addressed and authenticated:
    - Contains manifest identifier (`fw_id` or manifest digest), chunk index, and total chunk count.
    - Uses AEAD with a nonce construction compatible with ADR-002 and ADR-018.
    - Is bound to a specific device or device group to mitigate cross-device replay.
- Transfer protocol:
  - The device announces **OTA readiness** in regular uplinks (e.g., via a flag or a dedicated message type):
    - Includes currently running `fw_id`, battery condition, and free flash state.
  - The gateway schedules downlink chunks in RX windows (Class A-style).
  - The device:
    - Receives and validates each chunk.
    - Writes chunks to the candidate slot with integrity checks (e.g., per-chunk CRC).
    - Tracks which chunks are received; periodically includes missing-chunk bitmaps or ranges in uplinks to support selective retransmission.
  - Upon receiving all chunks, the device:
    - Verifies the full image digest matches the manifest `image_digest`.
    - Marks the candidate slot as ready for boot; actual slot switch is orchestrated by the bootloader.

### Operator Control and Rarity

- OTA is **operator-initiated and rare**, not an automatic background mechanism:
  - Only authorized operators (as per TrackOne's operational policy) can:
    - Approve manifests for deployment to specific fleets.
    - Trigger OTA campaigns via the gateway/control plane.
  - Defaults:
    - No OTA transfer is attempted unless:
      - The device is in an allowed state (e.g., sufficient battery, good link).
      - The operator has explicitly scheduled an update campaign.
- All OTA-related decisions and events are recorded in the TrackOne ledger (ADR-024):
  - Manifest approvals.
  - Campaign definitions (fleet, site, time range).
  - Success/failure outcomes for each device.

### Relationship to ADR-025 and Existing ADRs

- OTA uses:
  - The same cryptographic primitives and RNG policy as ADR-001 and ADR-018.
  - The same chain of trust defined in ADR-019.
  - The same anti-replay and ledger principles as ADR-002 and ADR-024.
- OTA is **logically separate** from adaptive cadence (ADR-025):
  - ADR-025 controls how often devices send telemetry and listen for control messages.
  - ADR-026 defines a higher-cost, slow path for firmware distribution and boot control.
  - Cadence policies may be temporarily adjusted (via ADR-025) to facilitate an OTA campaign (e.g., more frequent uplinks during a scheduled update window), but:
    - The ADRs remain independent and can be implemented on different timelines.

## Consequences

### Positive

- **Long-lived, upgradable deployments**:
  - Devices can receive security patches and protocol upgrades without physical access.
- **Strong integrity and provenance**:
  - Firmware manifests and images are signed and verified per ADR-001 and ADR-019.
  - OTA decisions are anchored in the TrackOne ledger (ADR-024), ensuring auditability.
- **Resilient to failures**:
  - Dual-slot/rollback design avoids bricking devices on failed updates.
  - Chunked transfer with per-chunk and whole-image validation tolerates packet loss.
- **Clear separation of concerns**:
  - Firmware distribution is distinct from telemetry cadence.
  - Operators can reason about OTA as an explicit, higher-risk maintenance operation.

### Negative

- **Higher on-device complexity and resource requirements**:
  - Requires additional flash for dual slots and metadata.
  - Requires a more capable bootloader, potentially increasing development and certification costs.
- **Operational cost and risk**:
  - Poorly planned OTA campaigns could:
    - Exhaust device batteries (excessive downlink, extended update windows).
    - Violate regional RF duty cycle rules if not throttled.
  - Requires careful rollout planning and monitoring.
- **Slow and limited bandwidth**:
  - Large firmware images may take hours or days to fully transfer for sparse, lossy links.
  - OTA over LoRa is practical only for occasional, critical updates, not frequent feature delivery.

## Alternatives Considered

- **No OTA (physical access only)**:
  - Simplest implementation with no bootloader or LoRa transfer complexity.
  - Rejected for remote or harsh deployments where physical access is impractical.
- **Full LoRaWAN FUOTA (Firmware Update Over The Air) standard adoption**:
  - Pros:
    - Leverages standardized mechanisms, ecosystem tools.
  - Cons:
    - Adds dependency on a full LoRaWAN network server and FUOTA infrastructure.
    - May not align with TrackOne’s bespoke chain-of-trust and ledger integration.
  - We may later integrate with FUOTA or mirror its patterns where appropriate, but this ADR defines requirements we must satisfy regardless of the underlying stack.
- **Single-slot updates with in-place overwrite**:
  - Uses less flash, simpler in concept.
  - Rejected due to high bricking risk; power or link failures mid-update can leave devices unbootable.
- **Out-of-band firmware via local side channels (e.g., Wi-Fi, Bluetooth, USB)**:
  - Can be faster and more convenient in some scenarios.
  - Not always available in constrained, remote deployments and does not address the LoRa-only fleet case this ADR is concerned with.

## Testing & Migration

- **Pre-deployment testing**:
  - Bootloader:
    - Platform-specific tests of dual-slot switch, rollback, and self-check logic.
    - Fault-injection tests simulating power loss at critical points (e.g., mid-chunk write, pre/post-slot switch).
  - Manifest and verification:
    - Unit tests for manifest canonicalization, signing, and verification (ADR-001, ADR-003).
    - Integration tests verifying that devices reject:
      - Invalid signatures.
      - Mismatched `image_digest`.
      - Incompatible `target_hardware` or `required_min_fw_id`.
- **Gateway/control-plane testing**:
  - Simulated OTA campaigns against virtual fleets:
    - Chunk scheduling respecting duty cycle limits and RX windows.
    - Campaign pause/resume and abort behavior.
    - Comprehensive logging and ledger facts (ADR-024, ADR-019).
- **Migration**:
  - Early hardware revisions may not support OTA:
    - Mark these explicitly in inventory, and never schedule OTA campaigns for them.
  - New hardware revisions should:
    - Ship with a bootloader conforming to this ADR.
    - Expose metadata in telemetry indicating OTA capability and current `fw_id`.
  - OTA functionality should:
    - Be disabled by default in production until:
      - End-to-end tests on pilot fleets validate reliability.
      - Operational runbooks and monitoring dashboards are in place.
