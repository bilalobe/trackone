# ADR-029: Environmental Sensing Use-Cases and Daily Summary Metrics

**Status**: Superseded by [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
**Date**: 2025-12-15
**Updated**: 2026-04-19

## Supersession Note

This ADR has been collapsed into ADR-030.

ADR-030 is now the single active decision for environmental fact summary
encoding and duty-cycled anchoring. This ADR remains only as historical
background for analytics and dashboard requirements.

## Historical Scope

ADR-029 originally proposed daily environmental analytics such as min/max/mean,
standard deviation, percentiles, day-over-day deltas, stability indices, data
sufficiency flags, and outlier policy metadata.

The active commitment model is narrower:

- canonical `EnvFact` summaries commit only the stable fields accepted by
  ADR-030;
- richer daily metrics remain derived analytics unless later promoted by a
  separate ADR;
- SensorThings summary observations are projections over accepted facts; and
- analytics outputs are not commitment roots unless explicitly admitted into
  the evidence plane.
