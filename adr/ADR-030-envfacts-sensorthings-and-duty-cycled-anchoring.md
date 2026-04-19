# ADR-030: Environmental Evidence Model, Projections, and Duty-Cycled Anchoring

**Status**: Accepted
**Date**: 2025-12-15
**Updated**: 2026-04-19
**Supersedes**: [ADR-027](ADR-027-sensorthings-shtc3-representation.md), [ADR-028](ADR-028-sensorthings-projection-mapping.md), [ADR-029](ADR-029-env-daily-summaries-and-usecases.md)

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): core cryptographic primitives
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): telemetry framing and replay policy
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and OTS anchoring
- [ADR-006](ADR-006-forward-only-schema-and-salt8.md): forward-only schema discipline
- [ADR-014](ADR-014-stationary-ots-calendar.md): stationary OTS calendar direction
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): randomness and nonce policy
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): gateway chain of trust
- [ADR-020](ADR-020-stationary-ots-calendar-followup.md): stationary calendar implementation reality
- [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md): OTS pipeline safety net
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): anti-replay and ledger semantics
- [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md): duty-cycled uplink policy
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): transport versus commitment encodings
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): CBOR-first commitment authority
- [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md): TrackOne evidence-plane scope

## Context

TrackOne needs one active decision for environmental evidence. Earlier ADRs
split this into SHTC3 sensor representation, SensorThings projection mapping,
daily-summary analytics, and duty-cycled anchoring. That split was useful while
the model was still forming, but it now overstates SensorThings and analytics as
parallel architecture authorities.

The current architecture is narrower:

- TrackOne is the evidence plane.
- `trackone_core` owns the stable environmental `Fact` / `EnvFact` wire model.
- `rust-postcard-v1` is the supported framed plaintext transport profile.
- `trackone-canonical-cbor-v1` is the verifier-facing commitment profile.
- SensorThings and analytics outputs are derived projections unless a later ADR
  promotes them into the evidence contract.

This ADR consolidates ADR-027, ADR-028, and ADR-029 into one governing
environmental evidence decision.

## Decision

### 1. Canonical Environmental Fact Model

The canonical environmental payload is the Rust `EnvFact` model in
`trackone-core`. It is the shared source for pod firmware, gateway admission,
and verifier-facing artifact generation.

Conceptually:

```rust
pub struct PodId(pub [u8; 8]);
pub type DeviceId = PodId;
pub type FrameCounter = u64;

#[repr(u8)]
pub enum SampleType {
    AmbientAirTemperature = 1,
    AmbientRelativeHumidity = 2,
    InterfaceTemperature = 3,
    CoverageCapacitance = 4,
    BioImpedanceMagnitude = 5,
    BioImpedanceActivity = 6,
    SupplyVoltage = 7,
    BatterySoc = 8,
    FloodContact = 9,
    LinkQuality = 10,
    Custom = 250,
}

#[repr(u8)]
pub enum FactKind {
    Env = 1,
    Pipeline = 2,
    Health = 3,
    Custom = 250,
}

pub struct EnvFact {
    pub sample_type: SampleType,
    pub phenomenon_time_start: i64,
    pub phenomenon_time_end: i64,
    pub value: Option<f32>,
    pub min: Option<f32>,
    pub max: Option<f32>,
    pub mean: Option<f32>,
    pub count: Option<u32>,
    pub quality: Option<f32>,
    pub sensor_channel: Option<u8>,
}

pub enum FactPayload {
    Env(EnvFact),
    Custom(heapless::Vec<u8, 64>),
}

pub struct Fact {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub ingest_time: i64,
    pub pod_time: Option<i64>,
    pub kind: FactKind,
    pub payload: FactPayload,
}
```

Normative properties:

- `(pod_id, fc)` is the replay boundary. Replayed or stale frames never enter
  the Merkle set.
- `phenomenon_time_start` and `phenomenon_time_end` describe the observation
  window.
- `ingest_time` describes gateway acceptance time and maps to projection
  `resultTime`.
- Instant observations use `value` and normally `count = Some(1)`.
- Window summaries use `min`, `max`, `mean`, and `count`.
- `Custom` is an escape hatch and is not part of the stable environmental
  evidence contract.
- Canonical commitment bytes are CBOR under ADR-039. JSON remains projection
  and tooling output.

### 2. Sensor Capabilities Stay Out of Fact Bytes

SHTC3-class capability metadata is deployment or projection metadata, not
per-reading commitment content.

TrackOne may describe sensors with fields such as:

- `sensor_type`, for example `SHTC3`, `SHT31`, or `Generic_T_RH`;
- `sensor_vendor`;
- measurable quantities;
- units;
- resolution;
- accuracy and confidence class;
- operating range; and
- calibration date or notes.

Those fields belong in provisioning/deployment metadata, static firmware/gateway
tables, schema-backed projection inputs, or SensorThings `Sensor.metadata`.
They do not belong in every `EnvFact`.

Rationale:

- Facts stay compact for duty-cycled radio paths.
- Sensor metadata can change by creating new metadata records without changing
  historical readings.
- Commitment bytes stay focused on accepted observations rather than verbose
  descriptive context.

### 3. Raw and Summary Semantics

TrackOne commits a narrow summary shape.

Raw observations:

- `phenomenon_time_start == phenomenon_time_end`;
- `value = Some(reading)`;
- `count = Some(1)` when known; and
- aggregate fields are absent.

Window summaries:

- `phenomenon_time_start <= phenomenon_time_end`;
- `value = None` unless a later profile defines a single summary result;
- `min`, `max`, `mean`, and `count` carry the committed summary;
- `quality` may carry an implementation-defined quality score; and
- richer analytics stay outside the commitment contract.

Derived analytics may compute standard deviation, percentiles, day-over-day
deltas, stability indices, sufficiency flags, or outlier-policy metadata. Those
outputs are useful, but they are not canonical commitment fields unless a later
ADR explicitly admits them into the evidence plane.

### 4. SensorThings Is a Read-Only Projection

SensorThings is a deterministic projection over accepted TrackOne evidence. It
is not a commitment authority.

The gateway may emit schema-backed SensorThings-style bundles containing:

- `Thing` entities for pod deployments;
- `Sensor` entities from provisioning/deployment-backed sensor identity;
- `ObservedProperty` entities from `SampleType`;
- `Datastream` entities for stable `(Thing, Sensor, ObservedProperty, stream)`
  combinations; and
- `Observation` entities from accepted facts.

Projection rules:

- Entity IDs must be deterministic from canonical identifiers and deployment
  metadata.
- Observation `phenomenonTime` comes from `EnvFact.phenomenon_time_*`.
- Observation `resultTime` comes from `Fact.ingest_time`.
- Raw observations project scalar `value`.
- Summary observations project structured `{min, max, mean, count, quality, sensor_channel}` style results.
- Public SensorThings surfaces are read-only with respect to the core ledger
  unless a later ADR accepts a write-through model.
- Projection bundles are regenerable and schema-backed, but they are not
  Merkle leaves and do not replace canonical fact/day CBOR.

### 5. Duty-Cycled Uplink and Daily Anchoring

Environmental evidence follows the duty-cycled posture from ADR-025.

Pods:

- sample locally at deployment-defined cadence;
- aggregate locally when needed;
- transmit sparse `EnvFact` frames, commonly 1-4 times per day;
- keep payloads within the fixed framed payload budget; and
- open short receive windows after uplink for optional ACK or policy updates.

Gateways:

- validate frames and enforce replay state before admission;
- write accepted facts into the evidence set;
- batch accepted facts into daily `day.cbor` artifacts;
- compute Merkle roots from authoritative commitment bytes;
- produce block/day records and verification manifests; and
- anchor day artifacts with OTS and optional adjacent channels.

Duty cycling preserves verifiability because every accepted fact is admitted
once, assigned to a deterministic day artifact, and recomputable by a verifier
from the published evidence bundle.

## Consequences

### Positive

- One ADR now governs environmental evidence, metadata, projection, and
  duty-cycled anchoring.
- SensorThings is clearly a derived integration view, not a parallel authority.
- `EnvFact` stays small enough for constrained framed transport.
- Daily summaries have a stable committed shape while leaving analytics room to
  evolve outside commitment bytes.
- Historical ADR links remain valid through ADR-027, ADR-028, and ADR-029
  supersession stubs.

### Negative / Tradeoffs

- ADR-030 is broader than a narrowly scoped ADR.
- Rich SHTC3 metadata and analytics are no longer accepted commitment fields by
  default; consumers must treat them as metadata or derived outputs.
- SensorThings implementers must understand the evidence/projection boundary
  instead of treating SensorThings as the source of truth.

## Alternatives Considered

- Keep ADR-027 through ADR-030 as separate active records: rejected because it
  makes SensorThings and derived analytics look more central than they are.
- Delete ADR-027 through ADR-029: rejected because it breaks historical links
  and makes prior review context harder to follow.
- Promote daily analytics into canonical facts now: rejected because the current
  implementation only commits the narrower `EnvFact` summary shape.

## Implementation Notes

- `crates/trackone-core/src/types.rs` implements the active `Fact`, `EnvFact`,
  `SampleType`, and `SensorCapability` types.
- `crates/trackone-gateway/src/sensorthings/` and
  `trackone_core.sensorthings` own deterministic SensorThings projection
  helpers.
- `toolset/unified/schemas/env_sensor_capability.schema.json` is metadata
  contract material, not a per-fact commitment schema.
- `toolset/unified/schemas/sensorthings_projection.schema.json` describes the
  derived projection artifact.
- `scripts/gateway/sensorthings_projection.py` is orchestration over the native
  projection helpers.
