# ADR-027: Representation of SHTC3-Class Sensors and Environmental Readings

**Status**: Superseded by [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
**Date**: 2025-12-15
**Updated**: 2026-04-19

## Supersession Note

This ADR has been collapsed into ADR-030.

ADR-030 is now the single active decision for:

- the canonical environmental `EnvFact` wire model;
- SHTC3-class sensor capability metadata placement;
- raw versus summary observation encoding;
- deterministic SensorThings projection semantics; and
- duty-cycled `day.cbor` anchoring.

This file is retained only to preserve historical links and ADR numbering. Do
not treat the field shapes proposed here as current authority.

## Historical Scope

ADR-027 originally proposed a dedicated SHTC3-class sensor representation,
including capability metadata, resolution/accuracy handling, and raw-versus-
summary reading fields.

The active implementation chose a smaller `EnvFact` commitment model:

- sensor capabilities live out of band, not inside every fact;
- raw observations use `value`;
- window summaries use `min`, `max`, `mean`, and `count`; and
- richer uncertainty, calibration, and integration metadata are projection or
  analytics concerns unless a future ADR promotes them into the commitment
  contract.
