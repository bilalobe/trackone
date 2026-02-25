# ADR-030: EnvFact schema, SensorThings alignment, and duty-cycled day.cbor anchoring

**Status**: Accepted
**Date**: 2025-12-15
**Updated**: 2026-02-25

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Core cryptographic primitives (cryptographic basis)
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and OTS anchoring (ledger anchoring)
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): Replay window and device table (anti-replay semantics)
- [ADR-006](ADR-006-forward-only-schema-and-salt8.md): Forward-only schema and salt8 (schema discipline)
- [ADR-014](ADR-014-stationary-ots-calendar.md): Stationary OTS calendar (CI infrastructure)
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy (security baseline)
- [ADR-019](ADR-019-rust-gateway-chain-of-trust.md): Gateway chain of trust (verification and deployment)
- [ADR-020](ADR-020-stationary-ots-calendar-followup.md): Stationary OTS calendar follow-up (operational context)
- [ADR-021](ADR-021-safety-net-ots-pipeline-verification.md): Safety-net OTS pipeline verification (verification assurance)
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger (ledger semantics)
- [ADR-025](ADR-025-adaptive-uplink-cadence-over-lora.md): Adaptive uplink cadence (duty cycling)
- [ADR-027](ADR-027-sensorthings-shtc3-representation.md): SHTC3-class sensors and environmental readings (sensor metadata)
- [ADR-028](ADR-028-sensorthings-projection-mapping.md): Mapping TrackOne canonical facts to OGC SensorThings API (presentation layer)
- [ADR-029](ADR-029-env-daily-summaries-and-usecases.md): Environmental sensing use-cases and daily summary metrics (use-case definition)

## Context

Over the last iterations we:

- Introduced a Rust core crate (`trackone-core`) with a forward‑only Fact / EnvFact schema used by both pod firmware and gateway.
- Aligned the environmental telemetry model with OGC SensorThings API concepts (`Thing`, `Datastream`, `Observation`, `phenomenonTime`, `resultTime`).
- Tightened the anchoring pipeline to produce one canonical `day.cbor` per day, verified and stamped via Merkle + OpenTimestamps, as described in ADR‑014/020/024.
- Quantified power and airtime budgets that motivate duty‑cycled uplink (1–4 summary frames per day) instead of continuous or high‑rate streaming.
- Validated that the TrackOne protocol and frame builder fit comfortably on Cortex‑M0+/M4 with very small flash/RAM footprints, and that gateway‑side verification remains practical.
- Noted that schema and Merkle/OTS details were scattered across prose and test code; we need a single architectural decision that:
  - fixes the wire‑level schema for environmental facts,
  - clarifies projection into SensorThings/ArcGIS and into the ledger,
  - connects duty cycling (uplink frequency, RX windows) with verifiability and energy goals,
  - lets the report and codebase evolve without duplicating rationale.

## Decision

We adopt a unified environmental fact model and duty‑cycled anchoring strategy as follows.

### Canonical Fact / EnvFact schema (`trackone-core`)

The core Rust crate `trackone-core` defines the canonical schema for environmental observations on the wire.

```rust
pub struct PodId(pub [u8; 8]); // canonical device identifier
pub type DeviceId = PodId;
pub type FrameCounter = u64; // forward-only anti-replay counter

#[repr(u8)]
pub enum SampleType {
    AmbientAirTemperature   = 1,
    AmbientRelativeHumidity = 2,
    InterfaceTemperature    = 3,
    CoverageCapacitance     = 4,
    BioImpedanceMagnitude   = 5,
    BioImpedanceActivity    = 6,
    SupplyVoltage           = 7,
    BatterySoc              = 8,
    FloodContact            = 9,
    LinkQuality             = 10,
    Custom                  = 250,
}

#[repr(u8)]
pub enum FactKind {
    Env      = 1,
    Pipeline = 2,
    Health   = 3,
    Custom   = 250,
}

pub struct EnvFact {
    pub sample_type: SampleType,
    pub phenomenon_time_start: i64,   // seconds since epoch
    pub phenomenon_time_end:   i64,   // seconds since epoch
    pub value: Option<f32>,           // instantaneous or summary result
    pub min:   Option<f32>,
    pub max:   Option<f32>,
    pub mean:  Option<f32>,
    pub count: Option<u32>,
    pub quality:       Option<f32>,   // [0,1] or application-specific
    pub sensor_channel: Option<u8>,   // e.g. ADC channel, bus index
}

pub enum FactPayload {
    Env(EnvFact),
    Custom(heapless::Vec<u8, 64>),
}

pub struct Fact {
    pub pod_id: PodId,
    pub fc: FrameCounter,
    pub ingest_time: i64,         // gateway arrival / resultTime (seconds)
    pub pod_time: Option<i64>,    // device local time if available
    pub kind: FactKind,
    pub payload: FactPayload,
}
```

Key properties:

- Forward‑only anti‑replay: the tuple `(pod_id, fc)` is unique and monotonically increasing per device (see ADR‑024). Replayed or stale frames never enter the Merkle set.
- Time semantics:
  - `phenomenon_time_*` = when the environment was observed (SensorThings `phenomenonTime`).
  - `ingest_time` = when the gateway accepted the fact (SensorThings `resultTime` / ledger timestamp).
- Payload semantics:
  - `EnvFact` supports instantaneous observations (`value`, `count = 1`) and windowed summaries (`min`, `max`, `mean`, `count`).
  - `Custom` is an escape hatch for experimental payloads; not part of the heritage pipeline contract.
- Compact and postcard‑friendly: enums use `repr(u8)` (via `serde_repr`); the entire `Fact` serializes within `MAX_FACT_LEN` (256 bytes from `trackone-constants`), enforced by unit tests.

This schema is the single source of truth for pod firmware (`trackone-pod-fw`) and gateway (`trackone-gateway`). No parallel/proto or JSON‑only schemas are authoritative.

### Sensor metadata out of band

Sensor capabilities are kept out of the Fact wire schema:

```rust
pub struct SensorCapability {
    pub sample_type: SampleType,
    pub resolution: f32,
    pub accuracy:  f32,
    pub unit_symbol: &'static str,  // e.g. "°C", "%"
    pub label:       &'static str,  // e.g. "SHTC3 ambient RH/T"
}
```

These are defined in `trackone-core` for reuse, but exchanged:

- As static tables in firmware and gateway code; and/or
- Via metadata endpoints (e.g. SensorThings `Sensor` and `unitOfMeasurement`, or gateway introspection APIs).

Rationale:

- Avoids serialize/deserialize lifetime issues (`&'static str`) in the core fact stream.
- Keeps facts small and stable; metadata is not paid per reading.
- Matches SensorThings, where sensor/unit metadata live outside `Observation`.

### SensorThings / ArcGIS projection

The gateway maps `Fact` → SensorThings model; pods never speak SensorThings directly.

Standardized mapping:

- Thing: a pod deployment (identified by `PodId`, plus site/location metadata from provisioning DB).
- Location / FeatureOfInterest: site geometry (shaft / khettara segment) or pod coordinates.
- Datastream: (Thing, `SampleType`) pair (e.g. "Pod #7 Ambient RH").
- Observation:
  - `phenomenonTime`: `[EnvFact.phenomenon_time_start, EnvFact.phenomenon_time_end]`
  - `resultTime`: `Fact.ingest_time` (seconds → ISO 8601)
  - `result`: `EnvFact.value` if present, else `{ min, max, mean, count }`
  - `resultQuality` / parameters: carry `quality`, `sensor_channel`, and pointer back to the day record (`day_root`, `day.json` id)

This projection is a view. Canonical truth remains:

- the `facts/` directory,
- `day/` blobs and records,
- Merkle roots and OTS proofs as in ADR‑014/020.

SensorThings/ArcGIS are presentation and integration layers, not the root of trust.

### Duty‑cycled uplink and daily `day.cbor` anchoring

Adopt a daily anchoring cadence and duty‑cycled radio policy.

Pods:

- Sample sensors locally at higher cadence (e.g. every 5–15 minutes).
- Aggregate into `EnvFact` windows (min/max/mean/count) per uplink period.
- Transmit 1–4 `EnvFact`‑bearing frames per day (1/day baseline, 3–4/day during events), staying within a fixed payload budget (`< 256` bytes).
- Use Class A‑like RX: after each uplink, open a short RX window to receive optional ACK / policy updates. No continuous listening.

Gateway:

- Validates and stores incoming `Fact`s in `facts/` (anti‑replay, schema validation, site routing).
- Batches facts into one `day.cbor` per site per day at or just after day boundary (UTC or configured site local time).
- Computes the Merkle root over that day’s accepted facts and writes the corresponding `day.json` / block header.
- Runs OTS anchoring:
  - Stamp the day’s Merkle root / `day.cbor` at day close.
  - Upgrade pending proofs over hours/days until Bitcoin attestation is available (per ADR‑014/020/021).
- Exposes verification and status via local CLI/tools (`verify_cli`), SensorThings view, and optional dashboards.

Duty cycling preserves verifiability because:

- every accepted fact is in exactly one `day.cbor`,
- every `day.cbor` is anchored (or explicitly marked pending/failed),
- SensorThings/ArcGIS consume anchored or anchor‑pending daily summaries.

## Alternatives Considered

- Pods emitting SensorThings/JSON directly over LoRa — rejected due to payload bloat, tight coupling, and difficulty preserving the `(pod_id, fc)` anti‑replay invariant.
- Per‑reading anchoring (OTS for every frame) — rejected because of operational load, energy/bandwidth cost, and poor value versus daily anchors.
- Embedding full sensor metadata in every Fact — rejected due to wire bloat, lifetime/alloc constraints in `no_std`, and misalignment with SensorThings separation.
- Gateway‑only proprietary schema (no core crate) — rejected because a shared crate (`trackone-core`) ensures consistent anti‑replay, encoding, verification, and provides testable size/behavior constraints.

## Consequences

Positive:

- Single canonical schema: all Rust components consume/produce `Fact` / `EnvFact` from `trackone-core`.
- Schema changes centralized and checked via unit tests (roundtrips, size budgets).
- Clean SensorThings mapping and ArcGIS integration as presentation layers.
- Energy‑aware duty cycling: focus on 1–4 uplinks/day and short RX windows; frequency controlled by rare downlink policy messages.
- Anchoring discipline: `day.cbor` and Merkle roots remain the anchoring unit; anti‑replay aligned with ADR‑024.
- Testable and portable: stress tests on Cortex‑M0+/M4 and QEMU confirm framing fits constrained targets; gateway and tools share parsing/validation paths.

Negative / Trade‑offs:

- Less intra‑fact introspection: richer context (site, wiring, capabilities) is external and requires lookups.
- Projection complexity concentrated in gateway; increases gateway responsibility.
- Daily anchoring granularity: smallest cryptographically anchored unit is 24 hours (configurable). Shorter windows (e.g., per‑hour) are possible but out of scope.

## Implementation Notes and Status

- Rust types described are implemented in `crates/trackone-core/src/types.rs` and re‑exported from `trackone-core::lib`.
- Frame encryption/decryption helpers in `crates/trackone-core/src/frame.rs` use `Fact` as the canonical payload, with `MAX_FACT_LEN` enforced via tests.
- Pod firmware (`crates/trackone-pod-fw`) builds against the new core types and will evolve to construct `EnvFact` via helpers and schedule duty‑cycled uplinks.
- Gateway crate (`crates/trackone-gateway`) is being aligned to:
  - accept `Fact` as its ingress type,
  - populate `facts/`,
  - batch into `day.cbor` and Merkle roots,
  - anchor with OTS,
  - expose SensorThings‑like views.
