# ADR-027 – Representation of SHTC3-Class Sensors and Environmental Readings

**Status**: Proposed
**Date**: 2025-12-15
**Related ADRs**:

- ADR-028: Mapping TrackOne canonical facts to OGC SensorThings API (projection)

- ADR-029: Environmental sensing use-cases and daily summary metrics (requirements)

- ADR-030: EnvFact schema and duty-cycled day.bin anchoring (canonical schema)

## Context

TrackOne ingests environmental measurements from SHTC3-class temperature/humidity sensors (and equivalent devices with similar characteristics):

- They expose:
  - Temperature (°C) and relative humidity (%) at fixed resolutions.
  - Manufacturer-specified **accuracy** bands (e.g. ±0.3 °C, ±2 %RH) that differ from **resolution** (e.g. 0.01 °C, 0.01 %RH).
- TrackOne already uses immutable "facts" as the canonical data model (see ADR-001, ADR-006, ADR-018).
- We are adding OGC SensorThings / ArcGIS integration, where Sensors and ObservedProperties must be described, and Observations can represent either:
  - **Raw** samples (per-reading values), or
  - **Summaries** (aggregates over a time window, e.g. hourly/daily).

We need a consistent way to:

1. Represent SHTC3-class sensor **capabilities and limitations** (resolution, accuracy, operating range).
1. Mark whether a reading is **raw** vs **summary**, and if summary: the aggregation semantics.
3. Expose enough metadata in both canonical facts and SensorThings API to support downstream analysis (e.g., uncertainty handling, quality checks, cross-site comparison).

## Decision

### 1. Canonical Sensor Capability Model

We define a generic capability model for SHTC3-class sensors (and similar T/RH sensors) at the **Sensor** level, not per-reading:

New canonical sensor fields (logical names, to be mapped into DB / structs):

- `sensor_type` (enum/string): MUST include concrete model when known, e.g. `"SHTC3"`, `"SHT31"`, `"Generic_T_RH"`.
- `sensor_vendor` (string): Manufacturer name, e.g. `"Sensirion"`.
- `measurable_quantities` (array of enums): e.g. `["temperature_air", "relative_humidity"]`.
- For each measurable quantity, we support a capability object:
- `unit` (string, UCUM): e.g. `"Cel"`, `"percent"`.
- `resolution` (float): Smallest representable increment in `unit` (e.g. `0.01`).
- `accuracy` (float): Manufacturer-stated typical absolute accuracy in `unit`, for normal operating range.
- `accuracy_confidence` (enum): e.g. `"typical"`, `"max"`, `"guaranteed"`, `"unknown"`.
- `operating_range` (min, max; same unit).
- `calibration_date` (optional datetime) and `calibration_notes` (string).

These capabilities are immutable once attached to a deployed physical sensor instance; changes (e.g. recalibration or sensor replacement) are modeled as new Sensor instances / versioned metadata, not mutable edits.

### 2. Raw vs Summary Environmental Readings

We differentiate **raw samples** from **summary aggregates** at the fact level:

New/clarified environmental reading fact fields:

- `sample_type` (enum): `"raw" | "summary"`.
- `phenomenon_time_start` (datetime).
- `phenomenon_time_end` (datetime).
  - For `sample_type="raw"`, `phenomenon_time_start == phenomenon_time_end` (instant).
  - For `sample_type="summary"`, they bound the aggregation window.
- `aggregation_method` (enum, nullable):
  - For `sample_type="raw"`: MUST be `null`.
  - For `sample_type="summary"`: MUST be one of `"min" | "max" | "mean" | "median" | "count" | "stddev" | "custom"`.
- `aggregation_window_id` (string/UUID, optional): Logical grouping key for multiple summary metrics over the same window (e.g. daily).

Environmental value fields (per quantity) are extended:

- `temperature_value` (float, optional).
- `temperature_uncertainty` (float, optional): 1-sigma or manufacturer accuracy, same unit.
- `humidity_value` (float, optional).
- `humidity_uncertainty` (float, optional).

For **raw samples**, `*_uncertainty` defaults to the sensor's **accuracy** for that quantity, unless improved calibration metadata is available.

For **summaries**, `*_value` should be the aggregate (e.g. mean, min, max) and `*_uncertainty` may reflect propagated uncertainty if available; otherwise, it can be left null and consumers fall back to sensor accuracies.

### 3. Exposure in SensorThings API

The SensorThings representation MUST follow:

- SHTC3-class device ⇒ Sensor entity with:
  - `name`: e.g. `"SHTC3 temperature and humidity sensor #123"`.
  - `description`: includes model, vendor, and free-text summary of capabilities.
  - `encodingType`: `"application/json"`.
  - `metadata`: JSON including the canonical capability fields:
    - `sensor_type`, `sensor_vendor`, `quantities`, `resolution`, `accuracy`, `operating_range`, `calibration`.
- `ObservedProperty` entities for:
  - `temperature_air` (with standard URIs / definitions where available).
  - `relative_humidity`.
- `Datastream` entities MUST include:
- `observationType`:
  - `"OM_Measurement"` for raw/scalar numeric values.
  - For summaries, we use `"OM_ComplexObservation"` when we carry multiple metrics (min/max/mean) in a single Observation result object.
- `unitOfMeasurement` appropriate to the quantity (°C, %).

We model **raw vs summary** via a combination of Datastream and Observation-level fields:

- For **pure raw streams**:
  - Use a dedicated Datastream (e.g. `"Air Temperature (raw samples)"`) with `observationType = OM_Measurement`.
  - Each Observation uses the canonical `temperature_value` or `humidity_value`.
- For **pure summary streams** (e.g. daily aggregates):
- Use another Datastream (e.g. `"Air Temperature (daily summary)"`), with:
  - `observationType = OM_ComplexObservation`.
- Each Observation `result` is a JSON object with fields such as `min`, `max`, `mean`, `count`, `stddev`.
- `phenomenonTime` carries the `[start, end]` summary window.

Mixed Datastreams (raw + summaries) are discouraged. If needed, they must encode `sample_type` in `resultQuality` or an extension property and be clearly documented; but the default is **separate Datastreams per sample_type**.

### 4. Resolution vs Accuracy Policy

- **Resolution** is treated as a **formatting/quantization** constraint: values in facts and Observations should not claim finer resolution than the underlying sensor supports.
- **Accuracy** is treated as **uncertainty**: it is never silently "baked in" to the value but is:
- Exposed in Sensor metadata and/or uncertainty fields in Observations.
- Used in downstream QC/analysis, but not for retroactive adjustment of the measurements.

## Consequences

- We have a uniform way to describe SHTC3-class sensor behavior and limitations in both internal facts and SensorThings resources.
- Downstream analytics can distinguish raw and summary readings, and can reason about uncertainty.
- Separate Datastreams for raw vs summary simplify ArcGIS/SensorThings integrations but require additional stream management and documentation.
- Schema changes must be implemented across ingestion, storage, and export layers.

## Required Schema and Data Field Changes

At minimum, we need:

- Canonical sensor metadata schema:

  - Add fields: `sensor_type`, `sensor_vendor`, `measurable_quantities`, and per-quantity capability objects (`unit`, `resolution`, `accuracy`, `accuracy_confidence`, `operating_range`, `calibration_date`, `calibration_notes`).

- Environmental reading fact schema:

  - Add `sample_type`, `aggregation_method`, `aggregation_window_id`, `phenomenon_time_start`, `phenomenon_time_end`.
  - Add or formalize `temperature_value`, `temperature_uncertainty`, `humidity_value`, `humidity_uncertainty`.

- SensorThings export:

  - Ensure Sensor `metadata` JSON embeds the above capability model.

  - Introduce separate Datastream definitions for raw and summary streams per quantity.
