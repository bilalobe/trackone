# ADR-026: Operator-Driven OTA Firmware Distribution over LoRa (NTN-Aware, Signed, Chunked, Dual-Slot)

**Status**: Proposed
**Date**: 2025-12-15
**Updated**: 2026-03-05

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Core cryptographic primitives
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Telemetry framing and replay policy
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Gateway chain of trust
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): OTS-backed ledger semantics
- [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md): Adaptive uplink cadence and authenticated downlink policy
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): Duty-cycled operational context
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Transport vs commitment boundary
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment profile

## Context

- OTA firmware is not part of the initial TrackOne pod milestone, but some deployments will be too remote or too costly to service physically.
- The target pods are still constrained LPWAN devices:
  - sparse uplinks;
  - short downlink receive windows;
  - strict power and regulatory budgets;
  - flash and bootloader limitations.
- A firmware image is materially larger and riskier than the cadence-control policies defined in ADR-025.
- The chain of trust must stay unified:
  - one authority model for manifests, signatures, and ledger facts;
  - one anti-replay story for pod/gateway interaction;
  - no separate OTA trust domain.
- ADR-039 now makes canonical CBOR the authoritative commitment format. This ADR must not keep older JSON-as-canonical language.
- In 2025-2026, non-terrestrial LoRa is no longer hypothetical. Satellite / NTN variants, especially LoRaWAN-over-satellite ecosystems, are becoming relevant for sparse remote coverage. That changes reachability options, but it does not remove the cost, latency, or campaign-risk profile of firmware delivery.

This ADR defines the architectural contract for firmware distribution and activation. It does not standardize a specific MCU bootloader implementation, radio vendor, or satellite provider.

## Decision

TrackOne will treat OTA firmware as a **rare, operator-driven maintenance operation** carried over the existing LoRa control plane, with an optional NTN transport profile.

The design has five hard requirements:

1. Firmware release artifacts are authenticated by the same chain of trust used elsewhere in TrackOne.
1. Canonical commitment bytes are CBOR-first, with JSON only as a projection.
1. Devices use dual-slot (A/B) or equivalent rollback-safe installation.
1. Ledger facts distinguish between firmware publication, delivery attempts, application, and rollback.
1. NTN-LoRa / LoRaWAN-over-satellite is a transport extension, not a semantic fork.

### Firmware Release Artifact

- Each release defines a canonical **Firmware Manifest**.
- The authoritative artifact is deterministic CBOR, consistent with ADR-034 and ADR-039.
- A JSON rendering may be emitted for operator inspection, but it is not authoritative.
- The manifest includes:
  - `manifest_id`: stable identifier for this release artifact;
  - `fw_id`: firmware version/build identifier;
  - `target_hardware`: compatible board / MCU / radio profile;
  - `image_digest`: SHA-256 of the full candidate image;
  - `image_size_bytes`;
  - `chunk_size_bytes`;
  - `required_min_fw_id` (optional);
  - `release_channel` (for example `stable`, `pilot`, `emergency_patch`);
  - `activate_delay_s` (optional, relative to confirmed receipt);
  - `campaign_ttl_s` (optional, relative validity window for transfer completion);
  - `metadata` (optional operator notes or flags).
- The manifest is signed with a TrackOne firmware authority key rooted in the gateway chain of trust.
- The ledger may anchor the manifest digest and deployment scope, but the authoritative release artifact remains the signed CBOR manifest plus the image digest it authorizes.

### Device Boot and Rollback Contract

- OTA-capable pods must implement dual-slot (A/B) or an equivalent rollback-safe arrangement.
- The pod maintains:
  - `slot_active`: the currently running known-good image;
  - `slot_candidate`: the staging slot for a new image;
  - minimal boot metadata indicating pending activation, confirmation state, and rollback reason if any.
- The bootloader or equivalent early-boot stage MUST:
  - verify the manifest signature against an embedded trust anchor;
  - verify the candidate image digest against `image_digest`;
  - refuse activation if `target_hardware` or upgrade constraints do not match;
  - require post-boot confirmation before marking the candidate as good.
- If boot confirmation fails, the device MUST roll back to the last known-good slot and report the rollback on the next available uplink.

### Transfer Protocol over LoRa

- OTA transfer reuses the authenticated downlink model from ADR-025 rather than inventing a parallel control channel.
- A campaign begins with a pod receiving and authenticating the firmware manifest or a compact manifest offer bound to `manifest_id`.
- The pod explicitly acknowledges manifest acceptance before bulk transfer begins.
- Firmware chunks:
  - are bound to `manifest_id` or the manifest digest;
  - carry chunk index and total-count metadata;
  - are authenticated with the downlink trust model used for control-plane traffic;
  - may be retransmitted selectively based on pod-reported gaps.
- The pod reports OTA state through authenticated uplink status, including:
  - current `fw_id`;
  - `manifest_id` in progress, if any;
  - transfer completeness / missing ranges;
  - final states such as `applied`, `rejected`, `rolled_back`, or `aborted`.
- Time handling is receipt-relative:
  - `activate_delay_s` starts when the pod confirms receipt of a valid manifest;
  - `campaign_ttl_s` is evaluated relative to the accepted campaign state, not against an assumed accurate RTC.

### Ledger and Audit Semantics

- Lifecycle stage MUST separate OTA-related facts. At minimum:
  - `fw_manifest_published`;
  - `fw_campaign_scheduled`;
  - `fw_transfer_started`;
  - `fw_applied`;
  - `fw_rollback` or `fw_failed`.
- The gateway MUST NOT record `fw_applied` merely because it issued a campaign.
- Pod-originated confirmation is required before the ledger claims a pod accepted or applied firmware.
- These facts allow later audits to distinguish:
  - what was authorized;
  - what was actually delivered;
  - what the pod claims it installed;
  - whether rollback occurred.

### NTN Transport Profile

- TrackOne remains designed around sparse, duty-cycled pod behavior. Terrestrial LoRa is still the baseline deployment assumption.
- NTN-LoRa is treated as an additional transport profile for remote fleets where terrestrial gateways are infeasible.
- In practice, current NTN options are most likely to arrive through LoRaWAN-over-satellite or a relay architecture rather than raw terrestrial-style LoRa links.
- This ADR does not require TrackOne to adopt a specific NTN provider or a full LoRaWAN stack.
- If an NTN profile is introduced, it MUST preserve:
  - the same signed manifest format;
  - the same digest and chunk semantics;
  - the same bootloader validation rules;
  - the same ledger fact model.
- NTN changes campaign assumptions, not firmware authority semantics:
  - coverage may improve;
  - latency may become less predictable;
  - downlink opportunities may remain scarce and expensive;
  - large images still remain exceptional operations.
- NTN therefore improves reachability for manifest offers, sparse control traffic, and critical recovery cases more than it makes routine large-scale firmware rollout attractive.

## Consequences

### Positive

- OTA is no longer described as a vague future capability; the trust and audit boundaries are explicit.
- The ADR now aligns with TrackOne's accepted CBOR-first artifact model.
- Operators get a clear distinction between:
  - firmware publication;
  - transfer attempts;
  - confirmed application;
  - rollback.
- The design remains usable across terrestrial LoRa and future NTN transport variants without redefining firmware provenance.

### Negative

- OTA remains operationally expensive and slow for sparse duty-cycled pods.
- Dual-slot support raises flash, bootloader, and testing requirements.
- NTN does not solve the core bandwidth problem for large images; it only changes coverage and control-plane reachability.
- Any future LoRaWAN-over-satellite integration will still need an explicit mapping from TrackOne's trust model to the chosen network stack.

## Alternatives Considered

- **No OTA; physical servicing only**
  - Simplest and lowest-risk firmware model.
  - Rejected because some deployments will not be serviceable at acceptable cost or cadence.
- **Treat OTA as a normal background feature-delivery channel**
  - Rejected because the radio, duty-cycle, and power model do not support routine feature shipping.
- **LoRaWAN FUOTA as the normative design**
  - Rejected as the default because TrackOne still requires its own artifact authority, ledger semantics, and constrained-device assumptions.
  - If a LoRaWAN or NTN provider is used later, it must be treated as a transport realization of this ADR rather than the source of truth.
- **Single-slot overwrite**
  - Rejected because power loss or partial transfer can brick a pod.

## Testing & Migration

- Bootloader validation:
  - test slot switching, confirmation, and rollback under power-loss fault injection;
  - test rejection of mismatched `target_hardware`, bad signatures, and bad digests.
- Control-plane validation:
  - test manifest offer, pod acknowledgement, chunk transfer, resume, and abort flows;
  - verify that ledger facts never overclaim application before pod confirmation.
- Transport validation:
  - terrestrial LoRa remains the baseline test profile;
  - if NTN is introduced, run the same campaign-state tests under higher latency and sparser downlink assumptions.
- Migration:
  - pods lacking dual-slot support or sufficient flash are permanently non-OTA-capable inventory;
  - OTA stays disabled by default until pilot-fleet testing demonstrates acceptable battery, reliability, and rollback behavior.
