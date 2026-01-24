# ADR-033: Virtual Fleet for Verifiable Telemetry and End-to-End Validation

**Status**: Proposed
**Date**: 2026-01-04

## Related ADRs

- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): Informational RFC for verifiable telemetry ledgers
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and ledger semantics
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Randomness and nonce policy
- [ADR-028](ADR-028-sensorthings-projection-mapping.md) & [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): SensorThings projections and envfact schemas
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md) & [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): Anchoring and timestamping strategies

## Context

The project spans firmware/device constraints, a Python/Rust data path, and a verifiable ledger pipeline. Hardware pods are intermittently available, and some research questions remain unsettled (e.g., buffering strategy, durability limits, deployment conditions like submersion). This slows validation of end-to-end behavior and risks drift between “what we think the system does” and what it actually does.

We need a repeatable way to:

- Exercise ingestion → canonicalization → batching → anchoring flows without requiring physical devices.
- Test anti-replay, monotonic counters, clock skew, network outages, and recovery.
- Compare parallel implementations (Python/Rust) against the same scenarios.
- Produce artifacts suitable for review (deterministic logs, fixtures, proofs).

## Decision

Introduce a **Virtual Fleet** as a first-class architectural component used for development, validation, and documentation.

The Virtual Fleet is:

- A set of **simulated/emulated pods** producing telemetry events and meta-events (reboots, counter resets, outages, delayed uploads).
- A **scenario runner** that can deterministically replay time and generate reproducible event streams.
- A **fixture generator** that produces:
  - Raw telemetry payloads (and optional `.bin` fallbacks)
  - Canonicalized “facts” (as consumed by the ledger)
  - Expected Merkle roots / proofs for regression testing

It will be used to validate:

- Ledger semantics (append-only, anti-replay, monotonic counters).
- Anchoring workflows (e.g., OTS + RFC 3161) under degraded conditions.
- Projection outputs (e.g., SensorThings/envfact schemas) for a stable example dataset.

The Virtual Fleet is **not**:

- A substitute for hardware validation of physical constraints (battery aging, flash wear, waterproofing, RF behavior).
- A full “digital twin” of every analog behavior; it models protocol and data semantics first.

## Scope and Interfaces

### Inputs modeled

- Pod identity / key material (abstracted or test keys)
- Monotonic counters / nonces
- Clock behavior (skew, jump, drift) and timestamp policy
- Storage behaviors relevant to data semantics:
  - Buffered day-scale retention before publication
  - Fallback `.bin` export semantics (serialization format is out-of-scope here)
  - Reset/reboot events affecting counters and buffering

### Outputs produced

- Deterministic event logs (for replay)
- Pseudo-device batches (for ingestion)
- Expected ledger artifacts (roots, proofs, anchors metadata in test mode)

### Integration points

- Tests in `tests/e2e` (or equivalent): scenario-driven end-to-end pipeline validation.
- Reference implementation: non-normative examples aligned with ADR-032’s prospective RFC narrative.

## Consequences

### Positive

- Faster iteration without device availability.
- Reproducible regression tests for ledger correctness, anti-replay, and anchoring.
- Shared vocabulary for “pod behavior” that supports design discussions (e.g., buffering vs. wear constraints).
- Bridges multi-repo/codepath drift by running identical scenarios through Rust and Python components.

### Negative

- Risk of false confidence if simulation omits critical physical constraints.
- Requires careful determinism discipline (seed control, stable canonicalization).
- Adds maintenance burden for scenario definitions and fixtures.

## Alternatives Considered

- Only hardware-in-the-loop: highest fidelity but slow and non-deterministic for many failure cases.
- Only unit tests per component: doesn’t validate cross-component semantics (counters, replay rules, proofs).
- Third-party IoT simulators: may not model ledger semantics and canonicalization constraints well.

## Testing and Verification

- Add deterministic scenario suites:
  - Normal operation (daily buffering → publish)
  - Network outage (publish delay, batch ordering changes)
  - Reboot/reset sequences (counter continuity rules)
  - Clock anomalies (skew/jump) and policy enforcement
  - Replay attempts (duplicate batches, reordered uploads)
- Assert:
  - Identical canonical facts for equivalent inputs
  - Stable Merkle roots for deterministic inputs
  - Rejection/handling paths for anti-replay violations
  - Anchor records consistent with ADR-003/ADR-015 semantics (test anchors allowed)

## Notes

This ADR defines *why* the Virtual Fleet exists and the boundaries of correctness it targets. Physical durability topics (e.g., flash endurance for 5+ years, waterproofing/submersion) remain separate engineering decisions but can be informed by the Virtual Fleet’s workload models.
