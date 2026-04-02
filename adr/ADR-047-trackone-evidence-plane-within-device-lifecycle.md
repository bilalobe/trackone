# ADR-047: TrackOne as the evidence plane within a broader device lifecycle system

**Status**: Accepted
**Date**: 2026-04-02

## Related ADRs

- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): ledger semantics and anti-replay boundary
- [ADR-032](ADR-032-informational-rfc-verifiable-telemetry-ledger.md): I-D scope and interoperability posture
- [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md): trust and signature boundary discipline
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): authoritative artifact contract
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): verifier-facing disclosure model
- [ADR-046](ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md): trust-root and publication boundary

## Context

TrackOne began as a secure telemetry and verifiable-ledger workspace, but the
path from pod prototypes to a fleet of tens of thousands of deployed pods makes
one pressure point explicit: device identity, onboarding, credential issuance,
update management, network admission, telemetry integrity, and external
disclosure are related, but they are not one system.

Without a sharper boundary, TrackOne risks becoming an umbrella for:

- manufacturer identity and first ownership;
- network onboarding and domain admission;
- operational PKI and credential lifecycle;
- firmware/update orchestration;
- gateway admission and replay policy; and
- verifiable telemetry, artifacts, and disclosure.

That would broaden both the implementation and the Internet-Draft beyond a
coherent center of gravity.

At a fleet scale, the strongest technical and operational distinction is between:

- the lifecycle/control plane that decides which pods are known, onboarded,
  trusted, admitted, updated, or revoked; and
- the evidence plane that turns admitted telemetry into authoritative,
  verifiable records and disclosure artifacts.

## Decision

### TrackOne is the evidence plane, not the entire lifecycle plane

TrackOne's primary role is to accept already-admitted telemetry and produce
authoritative, reproducible, verifier-facing evidence.

TrackOne owns:

- gateway-side validation, anti-replay, and canonical record admission;
- deterministic batching into authoritative artifacts;
- artifact hashing, anchoring, and verifier-facing manifests; and
- disclosure/export behavior for independent verification.

TrackOne does not, by default, own:

- manufacturer identity issuance;
- initial network onboarding;
- fleet inventory or ownership registry;
- operational certificate authority policy;
- network access policy enforcement; or
- firmware/update orchestration.

### TrackOne depends on a separate lifecycle/control plane

For production deployment, TrackOne assumes an adjacent lifecycle/control plane
that can supply:

- device inventory and ownership state;
- onboarding and domain admission decisions;
- operational credentials or equivalent pod identity material;
- rotation, quarantine, and decommission policy; and
- update-state and software-baseline awareness.

That adjacent plane may be implemented with BRSKI/BRSKI-AE, PKI, MUD, SUIT,
RATS, or equivalent deployment-specific systems. TrackOne may consume their
results, but it does not become their umbrella specification.

### The operational handoff boundary is explicit

The handoff into TrackOne is:

- a known pod identity or deployment binding;
- successful domain admission under local policy; and
- accepted telemetry under the active gateway transport and replay contract.

From that point onward, TrackOne is responsible for canonicality and evidence.

Before that point, lifecycle systems are responsible for whether the pod should
be present, trusted, reachable, or allowed to send.

### Fleet lifecycle states remain visible even if they are not owned by TrackOne

A deployment at scale should model at least these pod states:

- manufactured;
- received;
- staged;
- onboarded;
- operational;
- quarantined;
- rotated;
- decommissioned; and
- transferred or reprovisioned.

TrackOne may record evidence about transitions that affect telemetry trust, but
the authoritative state machine for those transitions belongs to the lifecycle
plane, not the evidence plane.

## Consequences

### Positive

- Prevents TrackOne from collapsing into a general IoT platform.
- Gives the Internet-Draft a narrower and more defensible scope.
- Makes large-fleet architecture clearer: onboarding trust and telemetry
  verifiability are connected but not identical concerns.
- Preserves space for standard lifecycle components without forcing TrackOne to
  re-specify them.

### Negative

- TrackOne alone is not enough for secure fleet operation.
- Deployments must integrate at least one external identity/onboarding/update
  story before production rollout.
- Some operators may initially expect TrackOne to solve more of the lifecycle
  problem than it should.

### Neutral / clarified

- This ADR does not weaken TrackOne's integrity goals; it narrows where they
  begin.
- This ADR does not prevent future integration profiles for onboarding or
  attestation systems; it only prevents TrackOne from becoming the umbrella for
  those systems by default.

## Alternatives considered

### Make TrackOne the full device lifecycle platform

Rejected.

This would mix inventory, onboarding, PKI, network policy, updates, telemetry,
and publication into one expanding boundary. That would increase scope faster
than interoperability or reuse would justify.

### Keep the boundary implicit

Rejected.

At a fleet scale, the absence of an explicit boundary encourages architectural
drift and makes both product planning and standards positioning less coherent.
