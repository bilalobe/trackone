# ADR-027 – Representation of SHTC3-Class Sensors and Environmental Readings

**Status**: Proposed
**Date**: 2025-12-15
**Related ADRs**:

- ADR-028: Mapping TrackOne canonical facts to OGC SensorThings API (projection)

- ADR-029: Environmental sensing use-cases and daily summary metrics (requirements)

- ADR-030: EnvFact schema and duty-cycled day.bin anchoring (canonical schema)

- Introduce separate Datastream definitions for raw and summary streams per quantity.

  - Ensure Sensor `metadata` JSON embeds the above capability model.

- SensorThings export:

  - Add or formalize `temperature_value`, `temperature_uncertainty`, `humidity_value`, `humidity_uncertainty`.
  - Add `sample_type`, `aggregation_method`, `aggregation_window_id`, `phenomenon_time_start`, `phenomenon_time_end`.

- Environmental reading fact schema:

  - Add fields: `sensor_type`, `sensor_vendor`, `measurable_quantities`, and per-quantity capability objects (`unit`, `resolution`, `accuracy`, `accuracy_confidence`, `operating_range`, `calibration_date`, `calibration_notes`).

- Canonical sensor metadata schema:

At minimum, we need:

## Required Schema and Data Field Changes

- Schema changes must be implemented across ingestion, storage, and export layers.
- Separate Datastreams for raw vs summary simplify ArcGIS/SensorThings integrations but require additional stream management and documentation.
- Downstream analytics can distinguish raw and summary readings, and can reason about uncertainty.
- We have a uniform way to describe SHTC3-class sensor behavior and limitations in both internal facts and SensorThings resources.

## Consequences

- Used in downstream QC/analysis, but not for retroactive adjustment of the measurements.
- Exposed in Sensor metadata and/or uncertainty fields in Observations.
- **Accuracy** is treated as **uncertainty**: it is never silently “baked in” to the value but is:
- **Resolution** is treated as a **formatting/quantization** constraint: values in facts and Observations should not claim finer resolution than the underlying sensor supports.

### 4. Resolution vs Accuracy Policy

Mixed Datastreams (raw + summaries) are discouraged. If needed, they must encode `sample_type` in `resultQuality` or an extension property and be clearly documented; but the default is **separate Datastreams per sample_type**.

- `phenomenonTime` carries the `[start, end]` summary window.
- Each Observation `result` is a JSON object with fields such as `min`, `max`, `mean`, `count`, `stddev`.
  - `observationType = OM_ComplexObservation`.
- Use another Datastream (e.g. `"Air Temperature (daily summary)"`), with:
- For **pure summary streams** (e.g. daily aggregates):
  - Each Observation uses the canonical `temperature_value` or `humidity_value`.
  - Use a dedicated Datastream (e.g. `"Air Temperature (raw samples)"`) with `observationType = OM_Measurement`.
- For **pure raw streams**:

We model **raw vs summary** via a combination of Datastream and Observation-level fields:

- `unitOfMeasurement` appropriate to the quantity (°C, %).
  - For summaries, we use `"OM_ComplexObservation"` when we carry multiple metrics (min/max/mean) in a single Observation result object.
  - `"OM_Measurement"` for raw/scalar numeric values.
- `observationType`:
- `Datastream` entities MUST include:
  - `relative_humidity`.
  - `temperature_air` (with standard URIs / definitions where available).
- `ObservedProperty` entities for:
  - `sensor_type`, `sensor_vendor`, `quantities`, `resolution`, `accuracy`, `operating_range`, `calibration`.
  - `metadata`: JSON including the canonical capability fields:
  - `encodingType`: `"application/json"`.
  - `description`: includes model, vendor, and free-text summary of capabilities.
  - `name`: e.g. `"SHTC3 temperature and humidity sensor #123"`.
- SHTC3-class device ⇒ Sensor entity with:

The SensorThings representation MUST follow:

### 3. Exposure in SensorThings API

For **summaries**, `*_value` should be the aggregate (e.g. mean, min, max) and `*_uncertainty` may reflect propagated uncertainty if available; otherwise, it can be left null and consumers fall back to sensor accuracies.

For **raw samples**, `*_uncertainty` defaults to the sensor’s **accuracy** for that quantity, unless improved calibration metadata is available.

- `humidity_uncertainty` (float, optional).
- `humidity_value` (float, optional).
- `temperature_uncertainty` (float, optional): 1-sigma or manufacturer accuracy, same unit.
- `temperature_value` (float, optional).

Environmental value fields (per quantity) are extended:

- `aggregation_window_id` (string/UUID, optional): Logical grouping key for multiple summary metrics over the same window (e.g. daily).
  - For `sample_type="summary"`: MUST be one of `"min" | "max" | "mean" | "median" | "count" | "stddev" | "custom"`.
  - For `sample_type="raw"`: MUST be `null`.
- `aggregation_method` (enum, nullable):
  - For `sample_type="summary"`, they bound the aggregation window.
  - For `sample_type="raw"`, `phenomenon_time_start == phenomenon_time_end` (instant).
- `phenomenon_time_end` (datetime).
- `phenomenon_time_start` (datetime).
- `sample_type` (enum): `"raw" | "summary"`.

New/clarified environmental reading fact fields:

We differentiate **raw samples** from **summary aggregates** at the fact level:

### 2. Raw vs Summary Environmental Readings

These capabilities are immutable once attached to a deployed physical sensor instance; changes (e.g. recalibration or sensor replacement) are modeled as new Sensor instances / versioned metadata, not mutable edits.

- `calibration_date` (optional datetime) and `calibration_notes` (string).
- `operating_range` (min, max; same unit).
- `accuracy_confidence` (enum): e.g. `"typical"`, `"max"`, `"guaranteed"`, `"unknown"`.
- `accuracy` (float): Manufacturer-stated typical absolute accuracy in `unit`, for normal operating range.
- `resolution` (float): Smallest representable increment in `unit` (e.g. `0.01`).
- `unit` (string, UCUM): e.g. `"Cel"`, `"percent"`.
- For each measurable quantity, we support a capability object:
- `measurable_quantities` (array of enums): e.g. `["temperature_air", "relative_humidity"]`.
- `sensor_vendor` (string): Manufacturer name, e.g. `"Sensirion"`.
- `sensor_type` (enum/string): MUST include concrete model when known, e.g. `"SHTC3"`, `"SHT31"`, `"Generic_T_RH"`.

New canonical sensor fields (logical names, to be mapped into DB / structs):

We define a generic capability model for SHTC3-class sensors (and similar T/RH sensors) at the **Sensor** level, not per-reading:

### 1. Canonical Sensor Capability Model

## Decision

3. Expose enough metadata in both canonical facts and SensorThings API to support downstream analysis (e.g., uncertainty handling, quality checks, cross-site comparison).
1. Mark whether a reading is **raw** vs **summary**, and if summary: the aggregation semantics.
1. Represent SHTC3-class sensor **capabilities and limitations** (resolution, accuracy, operating range).

We need a consistent way to:

- **Summaries** (aggregates over a time window, e.g. hourly/daily).
- **Raw** samples (per-reading values), or
- We are adding OGC SensorThings / ArcGIS integration, where Sensors and ObservedProperties must be described, and Observations can represent either:
- TrackOne already uses immutable “facts” as the canonical data model (see ADR-001, ADR-006, ADR-018).
  - Manufacturer-specified **accuracy** bands (e.g. ±0.3 °C, ±2 %RH) that differ from **resolution** (e.g. 0.01 °C, 0.01 %RH).
  - Temperature (°C) and relative humidity (%) at fixed resolutions.
- They expose:

TrackOne ingests environmental measurements from SHTC3-class temperature/humidity sensors (and equivalent devices with similar characteristics):

## Context
