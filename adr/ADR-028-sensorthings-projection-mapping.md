# ADR-028 – Mapping TrackOne Canonical Facts to OGC SensorThings API

**Status**: Accepted
**Date**: 2025-12-15
**Related ADRs**:

- ADR-006: Forward-only schema and salt8 (schema versioning principles)
- ADR-018: Cryptographic randomness and nonce policy (immutability guarantees)
- ADR-024: Anti-replay and OTS-backed ledger (canonical fact semantics)
- ADR-027: SHTC3-class sensors and environmental readings (schema definition)
- ADR-029: Environmental sensing use-cases and daily summary metrics (use-case requirements)
- ADR-030: EnvFact schema and duty-cycled day.bin anchoring (fact model)

## Context

TrackOne stores immutable canonical facts (see ADR-001, ADR-006, ADR-018, ADR-019):

- Events (e.g., sensor readings, calibrations, deployments) are append-only.
- Facts can be re-projected into different views and schemas, including:
  - Time-series for analysis.
  - External APIs (e.g., OGC SensorThings) for interoperability and visualization (e.g., ArcGIS, dashboards).

We are adding a SensorThings-compliant API that:

- Exposes: `Thing`, `Location`, `Sensor`, `ObservedProperty`, `Datastream`, `Observation` resources.
- Must remain a **projection** over immutable facts:
  - No mutable state that can diverge from canonical facts.
  - Idempotent regeneration of SensorThings state from the fact log.

We need a precise mapping between TrackOne’s facts and SensorThings entities.

## Decision

### 1. Principle: SensorThings as a Derived Projection

- The SensorThings API is a **read-only projection** over TrackOne canonical facts.
- All SensorThings resources (Things, Locations, Sensors, ObservedProperties, Datastreams, Observations) can be:
  - Recomputed from the fact log given a stable mapping.
  - Regenerated for replay / verification (see ADR-021).
- No “write-only” SensorThings state is allowed. Any state that cannot be reconstructed from facts is disallowed.

### 2. Entity Mapping Overview

Logical mapping (names are conceptual; real schema will use existing entities where possible):

- Canonical **Site / Asset / Pod / Device** fact(s) ⇒ SensorThings `Thing`:

  - A `Thing` corresponds to a logical physical system being monitored (e.g., a pod, station, or sensor node).
  - `Thing.properties` includes:
    - TrackOne identifiers: `trackone_thing_id`, `pod_id`, `site_id`, etc.
    - Device model, firmware version, etc. (see ADR-017, ADR-019).

- Canonical **Location** facts ⇒ SensorThings `Location`:

  - TrackOne location facts (geo coordinates, elevation, validity windows) are mapped to one or more `Location` resources.
  - `Thing` ↔ `Location` relationships:
    - `Thing` can be linked to multiple `Location`s over time:
      - Each link is defined by TrackOne location facts and validity intervals.
    - SensorThings `Location.location` uses GeoJSON (Point or other geometry).
    - Location changes are modeled by:
      - New `Location` entity or updated `Thing`–`Location` association with time intervals; the mapping must be deterministic from facts.

- Canonical **Sensor deployment** facts ⇒ SensorThings `Sensor`:

  - Each physical sensor instance (e.g. an SHTC3 on board a pod) becomes at least one `Sensor`.
  - Sensor metadata and capabilities come from ADR-027.
  - `Sensor.metadata` contains TrackOne sensor identifiers (e.g. `trackone_sensor_id`).

- Canonical **environmental observation/datapoint** facts ⇒ SensorThings `Observation`:

  - Any valid environmental reading fact (raw or summary) becomes an `Observation`.
  - `Observation.result` value(s) depend on the Datastream type:
    - Raw numeric values for `OM_Measurement`.
    - JSON objects for summary `OM_ComplexObservation`.
  - `Observation.phenomenonTime` comes from `phenomenon_time_start` / `phenomenon_time_end`.
  - `Observation.resultTime` is typically the ingestion/anchor time, or equal to `phenomenon_time_end` if no other anchor is available.

- Canonical **metric / quantity** configuration ⇒ SensorThings `ObservedProperty`:

  - Each measurable quantity in TrackOne (e.g., temperature_air, relative_humidity, pressure, VOC, etc.) is mapped to a standardized `ObservedProperty`.
  - `ObservedProperty.definition` should reference a standard URI when available (OGC, CF, etc.).
  - `ObservedProperty.properties` includes TrackOne quantity identifiers.

- Canonical **data stream configuration** ⇒ SensorThings `Datastream`:

  - A `Datastream` groups Observations with the same:
    - Thing
    - Sensor
    - ObservedProperty
    - Phenomenon type (raw vs summary) and aggregate semantics (where applicable)
  - `Datastream.properties` includes:
    - TrackOne stream identifiers (`trackone_stream_id`, `sample_type`, `aggregation_method`, `aggregation_window` descriptors).

### 3. Identity and Key Mapping

- Each SensorThings entity ID MUST be derivable from TrackOne canonical identifiers and type names.
- We adopt a deterministic ID scheme (e.g. namespace + hashed canonical key) or a mapping table that is itself persisted as facts.
- Requirements:
  - Given a fact log snapshot, regenerating the SensorThings view yields the same IDs and relationships.
  - Deletion of canonical facts is not supported (append-only), therefore SensorThings entities are never “hard-deleted”; they may become inactive or have no Observations after a given time.

### 4. Immutability and Update Semantics

- If a canonical fact changes the effective interpretation (e.g. a corrected calibration or late-arriving location), we model it as:
  - New fact(s) that supersede prior ones via validity windows or precedence rules; the old facts remain.
  - The SensorThings view is recomputed to reflect the latest valid facts per time interval.
- SensorThings `PATCH`/`POST`/`DELETE` operations are either:
  - Disabled for clients; or
  - Accepted only as **write-through** operations that create new canonical facts and then propagate into the SensorThings view.
- For now, we assume **read-only** SensorThings API (all server-side generation).

### 5. Raw vs Summary Streams (Cross-Ref to ADR-027 & ADR-029)

- Each combination of:
  - Thing
  - Sensor
  - ObservedProperty
  - Sample type: `"raw"` vs `"summary"`
  - Aggregation method and window (for summaries)
- results in one distinct Datastream.

This ensures:

- Observation semantics are consistent within a stream.
- ArcGIS / clients can treat each Datastream as internally homogeneous.

## Consequences

- We get a clean, reproducible, audit-friendly SensorThings view tied tightly to immutable canonical facts.
- Operational complexity increases: SensorThings is no longer an ad-hoc API layer, but a deterministic projection that must honor identity and versioning rules.
- Some SensorThings clients expecting mutable resources (e.g. editing Sensor metadata directly) must be guided to use TrackOne-native channels (or we keep SensorThings strictly read-only).

## Required Schema and Data Field Changes

- Canonical model:
  - Ensure there are stable identifiers for:
    - `Thing`-equivalent entities (e.g., pod/station/device).
    - Sensors, ObservedProperties (quantities), Locations, and data streams.
  - Ensure observation facts include:
    - References to `Thing`, `Sensor`, `ObservedProperty`, and `stream`/`sample_type` mapping.
- SensorThings export layer:
  - Implement stable ID mapping policy from canonical identifiers to SensorThings entity IDs.
  - Support generation of:
    - `Thing`, `Location`, `Sensor`, `ObservedProperty`, `Datastream`, `Observation` with correct relationships.
  - Enforce read-only or write-through behavior for API mutations, with preference for read-only in the initial implementation.
- Documentation:
  - Document the canonical ↔ SensorThings mapping and ID scheme to support debugging and reproducibility.
