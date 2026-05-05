# ADR-058: Admission State and Rejection Audit Contract

**Status**: Accepted
**Date**: 2026-05-05

## Related ADRs

- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): telemetry framing and replay policy
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): anti-replay and OTS-backed ledger semantics
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): transport versus commitment encodings
- [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md): evidence plane within device lifecycle
- [ADR-053](ADR-053-beta-public-contract-spine.md): beta public contract spine

## Context

Rust now owns the supported framed-ingest hot path for validation, frame/fact
binding, replay checks, decrypt/admit behavior, and canonical accepted-fact
shaping. Python still owns workflow orchestration, file lifecycle, device-table
persistence, and wrapper-level audit emission.

The beta boundary needs to be explicit: accepted telemetry becomes commitment
material, while rejected input becomes operator-audit evidence.

## Decision

The admission boundary is split as follows.

Rust/native owners:

- supported framed-ingest profile validation;
- nonce/AAD and frame/fact binding checks;
- replay admission behavior;
- decrypt/admit error classification; and
- canonical accepted-fact shaping for the supported path.

Python/package wrapper owners:

- device-table file loading and persistence;
- replay-state persistence across workflow runs;
- rejection-audit NDJSON file emission;
- schema validation and CLI/file orchestration; and
- report composition around native admission decisions.

The public rejection-audit contract remains operator-audit evidence, not a day
commitment artifact. The JSON Schema is the authoritative machine-readable
contract for the record shape, and the package taxonomies are authoritative for
the allowed `reason` and `source` values that the schema must encode. The beta
record shape is:

- `device_id`
- `fc`
- `reason`
- `observed_at_utc`
- `frame_sha256`
- `source`

The beta record shape is additive-only. Removing fields, renaming fields, or
changing field semantics requires a new ADR or an explicit ADR update.

The source and reason taxonomies are closed package-level values and must match
the JSON Schema exactly. Unknown source/reason values and invalid frame
counters must fail closed before emission.

Device-table updates must preserve the accepted replay high-water mark,
`last_seen`, `msg_type`, and `flags` for the admitted device entry. File I/O
may remain Python-owned, but the update shape must be stable and tested at the
package boundary.

## Consequences

### Positive

- The repo stays honest about Rust owning admission semantics while Python owns
  persistence and orchestration.
- Rejection audit records become stable enough for operator review without
  becoming hidden commitment material.
- Tests can lock the boundary without requiring a Rust workflow executor.

### Negative

- Rejection taxonomy changes now require package, schema, and test updates
  together.
- Promoting rejection audit to public commitment evidence later would require a
  new artifact-family decision under ADR-053.

## Alternatives Considered

- Move the full workflow executor into Rust for beta.
  This was rejected because the current beta bar is boundary stability, not a
  broad executor migration.
- Leave rejection audit shape script-local.
  This was rejected because operator-audit evidence would drift from schemas
  and package taxonomy.

## Testing & Migration

1. Keep package-level tests for rejection record serialization, taxonomy
   validation, frame-counter validation, and device-table update shape.
1. Keep schema tests that compare rejection-audit schema enums to package
   taxonomies.
1. Keep integration tests for duplicate, out-of-window, parse, decrypt, and
   unknown-device rejection paths.
