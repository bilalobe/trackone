# ADR-028: Mapping TrackOne Canonical Facts to OGC SensorThings API

**Status**: Superseded by [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
**Date**: 2025-12-15
**Updated**: 2026-04-19

## Supersession Note

This ADR has been collapsed into ADR-030.

ADR-030 is now the single active decision for the read-only SensorThings
projection boundary. SensorThings remains a deterministic projection of accepted
TrackOne evidence artifacts; it is not a commitment authority and does not
participate in Merkle roots or verifier-facing canonical bytes.

This file is retained only to preserve historical links and ADR numbering.

## Historical Scope

ADR-028 originally described a standalone SensorThings mapping from canonical
facts to `Thing`, `Location`, `Sensor`, `ObservedProperty`, `Datastream`, and
`Observation` resources.

The active rule is now simpler:

- accepted facts and `day.cbor` artifacts are the evidence authority;
- SensorThings bundles are schema-backed derived artifacts;
- entity IDs and timestamps must be deterministic from canonical facts and
  provisioning/deployment metadata; and
- public SensorThings surfaces are read-only with respect to the core ledger
  unless a later ADR accepts a write-through model.
