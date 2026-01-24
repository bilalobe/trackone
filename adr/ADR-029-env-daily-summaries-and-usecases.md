# ADR-029: Environmental Sensing Use-Cases and Daily Summary Metrics

**Status**: Proposed
**Date**: 2025-12-15

## Related ADRs

- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger (ledger structure for summaries)
- [ADR-027](ADR-027-sensorthings-shtc3-representation.md): SHTC3-class sensors and environmental readings (sensor capabilities)
- [ADR-028](ADR-028-sensorthings-projection-mapping.md): Mapping TrackOne canonical facts to OGC SensorThings API (API projection)
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): EnvFact schema and duty-cycled day.bin anchoring (canonical schema)

## Context

TrackOne’s environmental sensing data (e.g., temperature, humidity from SHTC3-class sensors) serves several analytical and operational use-cases:

1. **Trend detection**:
   - Detect long-term drifts or seasonal patterns per site/sensor.
1. **Anomaly / event detection**:
   - Detect excursions beyond thresholds, sensor failures, and sudden changes.
1. **Cross-site comparison**:
   - Compare conditions across pods/sites/regions for benchmarking, QA, and environmental studies.
1. **Operational health**:
   - Verify sensor stability and detect calibration drifts or environmental instability.

To support these use-cases efficiently, we require a consistent set of **daily summaries** (and a general pattern that can extend to other windows like hourly).

## Decision

### 1. Primary Use-Cases

We explicitly support:

- **UC-1 – Daily trend detection**:
  - For each Thing/Sensor/quantity, compute daily aggregates:
    - Simple statistics (min/max/mean).
    - Measures of variability (standard deviation, number of samples).
- **UC-2 – Anomaly and excursion detection**:
  - Identify days with:
    - Values outside configured thresholds (per quantity).
    - Abrupt changes relative to previous day(s).
- **UC-3 – Cross-site comparison**:
  - Provide normalized daily metrics that are robust to sampling irregularities (e.g., uses mean and robust variability metrics rather than raw counts).
- **UC-4 – Sensor stability assessment**:
  - Provide “stability indices” that:
    - Quantify intra-day variability (independent of diurnal cycles where possible).
    - Track day-to-day baseline shifts.

### 2. Daily Summary Definition

- **Daily window**:
  - Default summary window is **UTC-based calendar day**: `[YYYY-MM-DDT00:00:00Z, YYYY-MM-DDT24:00:00Z)`.
  - The window is configurable by deployment, but this ADR standardizes UTC day as the canonical summary window; alternative windows must be explicitly labeled.

For each Thing/Sensor/ObservedProperty combination (e.g., temperature_air, relative_humidity), we compute:

**Core metrics:**

- `min` – minimum observed value in the window.
- `max` – maximum observed value in the window.
- `mean` – arithmetic mean of all valid samples.
- `count` – number of valid samples.
- `stddev` – sample standard deviation (if `count >= 2`, otherwise `null`/0 as defined).
- `p10`, `p50`, `p90` (optional but recommended) – percentiles for more robust variability measurement.

**Day-over-day deltas:**

For trend and anomaly detection, we compute per-day deltas against the **previous day** for key metrics:

- `mean_delta_prev_day` – `mean(today) - mean(yesterday)`.
- `max_delta_prev_day` – `max(today) - max(yesterday)`.
- `min_delta_prev_day` – `min(today) - min(yesterday)`.

These are computed only when both days have sufficient data (see data sufficiency below).

**Stability indices:**

We define two stability indices per day:

- `intra_day_stability_index` (0–1, higher = more stable):
  - Function of intra-day variability normalized to expected environmental variation.
  - Initially, we define it as:
    - `1 / (1 + (stddev / reference_scale))`, where `reference_scale` is quantity-specific (e.g. 5 °C for temperature).
    - This is intentionally simple and may be refined later; the detailed formula must be documented in code and docs.
- `inter_day_stability_index` (0–1, higher = more stable):
  - Function of day-over-day difference in mean:
    - `1 / (1 + (abs(mean_delta_prev_day) / reference_delta_scale))`, where `reference_delta_scale` is quantity-specific (e.g. 2 °C for temperature).

These indices are intended for **relative comparison and alerting**, not precise physical interpretation.

### 3. Data Quality and Sufficiency Rules

- **Data sufficiency for daily summary**:

  - A day is considered **sufficient** if:
    - `count >= N_min` samples (deployment-specific; default e.g. 24 for hourly samples).
    - Samples are distributed across the day such that at least `M` distinct hours have data (e.g. 8 hours).

- If sufficiency is not met:

  - Mark the day’s summary with a quality flag (e.g. `quality_flag = "insufficient_data"`).
  - Still compute metrics when possible, but treat them as low-confidence.

- **Outlier handling**:

  - Outlier rejection or robust statistics may be applied (e.g., excluding values outside sensor operating range or with QC flags).
  - Such rules must:
    - Be deterministic.
    - Be documented in the summary metadata (e.g. `outlier_policy`).

### 4. Representation in Canonical Facts

Daily summaries are stored as **summary observation facts** (see ADR-027):

- `sample_type = "summary"`.
- `aggregation_method = "daily_core"` (or similar enum distinguishing this summary type).
- `phenomenon_time_start` and `phenomenon_time_end` bound the UTC day.
- `aggregation_window_id` uniquely identifies the daily window per Thing/Sensor/ObservedProperty (e.g. `YYYY-MM-DDZ` + IDs).
- `result` (logical) includes:
  - `min`, `max`, `mean`, `count`, `stddev`, `p10`, `p50`, `p90`.
  - `mean_delta_prev_day`, `max_delta_prev_day`, `min_delta_prev_day`.
  - `intra_day_stability_index`, `inter_day_stability_index`.
  - `quality_flag`, `outlier_policy`, `data_sufficiency` flags.

These may be represented as structured fields or a typed JSON payload, but must be versioned to allow future extensions without breaking existing consumers.

### 5. Exposure via SensorThings API

For SensorThings, we standardize:

- **Dedicated Datastreams for daily summaries**:

  - One Datastream per:
    - Thing
    - Sensor
    - ObservedProperty
    - Summary type (`"daily_core"`, future: `"hourly_core"`, etc.)
  - `observationType = "OM_ComplexObservation"`.
  - `unitOfMeasurement` may be set to null or generic if multiple units appear in `result`, but MUST be documented.

- Each daily summary Observation has:

  - `phenomenonTime` = `[day_start, day_end)` interval.
  - `result` JSON object containing:
    - Metrics listed above.
  - `resultQuality` (optional) can carry additional QC codes.

Raw Observations and daily summary Observations are **never mixed in the same Datastream**.

## Consequences

- Analytics and dashboards can rely on a consistent daily summary schema across sites and sensors.
- Cross-site comparison and anomaly detection can be implemented with predictable fields and semantics.
- Additional storage and compute is required for summarization, but queries become much cheaper and more robust.
- The stability indices are opinionated; future refinements must be versioned and documented to keep interpretations stable.

## Required Schema and Data Field Changes

- Canonical model:

  - Add or confirm summary fact type with:
    - `sample_type`, `aggregation_method`, `aggregation_window_id`, `phenomenon_time_{start,end}`.
    - Summary result fields for core metrics, deltas, stability indices, and QC flags.
  - Define per-quantity configuration for:
    - `reference_scale`, `reference_delta_scale`, thresholds, outlier policy.

- Processing pipeline:

  - Implement daily summary computation job (per Thing/Sensor/ObservedProperty).
  - Implement data sufficiency and QC rules.
  - Store daily summary facts as first-class canonical events.

- SensorThings export:

  - Define Datastream templates for daily summaries.
  - Map summary facts to Complex Observations with standardized `result` schema.

- Documentation:

  - Document use-cases, daily metric definitions, and stability index formulas for internal teams and external integrators.
