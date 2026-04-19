# ADR-020: Follow-up on Stationary OTS Calendar (ADR-014)

**Status**: Accepted
**Date**: 2025-11-20
**Updated**: 2026-04-19

## Related ADRs

- [ADR-014](ADR-014-stationary-ots-calendar.md): Stationary OpenTimestamps Calendar for Deterministic Anchoring
- [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md): OTS verification in CI and Bitcoin headers policy
- [ADR-008](ADR-008-m4-completion-ots-workflow.md): Milestone M#4 completion and OTS verification workflow
- [ADR-015](ADR-015-parallel-anchoring-ots-rfc3161-tsa.md): Parallel Anchoring with OTS and RFC 3161 TSA

## Context

ADR-014 proposed a "stationary" (self-hosted) OpenTimestamps (OTS) calendar to
improve determinism and reduce reliance on public calendars in CI and
reproducible pipelines.

Since ADR-014, we have:

- Finalized M#4 with a production-ready Bitcoin-anchored OTS pipeline that
  **consumes existing public calendars** via `opentimestamps-client` and
  `ots_anchor.py`.
- Added a dedicated tox environment `ots-cal` and a GitHub Actions workflow
  to exercise OTS integration in CI.
- Introduced a container sidecar image `ots/calendar:latest` built from this
  repository under `docker/calendar/`, which currently runs a long-lived
  **OTS client sidecar** rather than a full HTTP calendar server.
- Verified that the gateway, `ots_anchor.py`, and verification CLI can be
  configured via `OTS_CALENDARS` to talk to internal or external calendar
  endpoints.

However, we have **not** yet implemented or adopted an actual HTTP OTS
calendar server that we own. The current container is intentionally a
**controlled stub/sidecar** that:

- Uses the same Python libraries we vend for OTS interaction
  (`opentimestamps`, `opentimestamps-client`).
- Runs `opentimestamps_client` periodically in a no-op mode to validate the
  toolchain.
- Keeps a long-lived process for CI integration, but does **not** accept
  HTTP requests or persist calendar state.

This ADR clarifies the gap between ADR-014's "stationary calendar" concept and
what we have actually built, and documents the decision **not** to build a
full HTTP calendar server yet.

## Problem

We need a clear, documented stance on:

- What the `ots-cal` tox environment and CI job currently guarantee.
- Why we are not yet implementing a full OpenTimestamps HTTP calendar
  server (with its own state, Merkle batches, and Bitcoin anchoring
  responsibilities).
- How this affects ADR-014's rollout plan and the future of a stationary
  calendar.

Without this, ADR-014 can be misread as "we now run our own calendar",
whereas in reality we:

- Still rely on public calendars for production anchoring.
- Use an internal container only as a **tooling/sidecar** to exercise the
  OTS client stack under controlled conditions.

## Decision

1. **Clarify scope of the stationary calendar for now**

   - The `ots/calendar:latest` container in this repository is **not** a
     full OTS calendar implementation.
   - It is a **sidecar** that:
     - Runs `opentimestamps-client` in a long-lived process.
     - Validates that the Python tooling and CLI wiring are correct inside
       a containerized environment.
     - Exposes a TCP port (8468) for future HTTP services, but does not
       currently implement the OTS calendar protocol.

1. **Keep production anchoring on public OTS calendars**

   - For Milestone M#4 and current production usage, we continue to use
     public calendars (e.g. `https://a.pool.opentimestamps.org`) as the
     source of OTS calendar functionality.
   - `OTS_CALENDARS` is used to order preference (e.g., a future internal
     calendar first, then public pools), but today that internal endpoint
     is a stub/sidecar rather than a full calendar.

1. **Define a realistic, future path to a real stationary calendar**

   We explicitly *defer* building a proprietary HTTP calendar server, and we
   document what would be required if/when we decide to:

   - Adopt or fork a reference OTS calendar implementation that:
     - Speaks the OpenTimestamps calendar protocol over HTTP.
     - Manages its own persistence, batching, and Bitcoin anchoring.
   - Or design a simplified internal HTTP API that only our tooling uses,
     trading off interoperability for control.

1. **Stabilize CI behavior via `ots-cal`**

   - The `ots-cal` tox environment and its corresponding GitHub Actions
     workflow are treated as **integration smoke tests** for the OTS
     client/tooling, *not* full protocol verification of an internal
     calendar.
   - `ots-cal` may set `RUN_REAL_OTS=1` and `OTS_STATIONARY_STUB=0` to
     exercise real-OTS client code paths against the configured calendar
     endpoint, but this does not make the local sidecar a first-party OTS
     calendar implementation.
   - We rely on the standard OTS pipeline and public calendars in the
     other OTS-related tox environments (`ots`, `slow`, etc.) for actual
     proof production and upgrade behavior.

## Rationale

### Why not build a real HTTP calendar server now?

Implementing a real calendar implies:

- A long-lived HTTP service that implements the OpenTimestamps calendar
  protocol (or a compatible internal variant).
- Persistent storage for
  - incoming timestamp requests,
  - batch/merkle state,
  - Bitcoin anchoring metadata.
- A Bitcoin anchoring responsibility of its own, coordinated with our
  existing pipeline and ADR-007 / ADR-008 / ADR-015.
- Operational considerations (durability, monitoring, migration, and ACLs)
  that are distinct from our current gateway and verification stack.

At this stage, the incremental value **for us** from owning a calendar
implementation, compared to:

- continuing to rely on well-known public calendars for anchoring, and
- exercising our own OTS client + anchoring pipeline end-to-end,

is not yet high enough to justify:

- designing and implementing a new server component,
- committing to its operational lifecycle,
- and potentially diverging from the upstream OTS ecosystem.

Instead, we:

- Focus M#4 on a robust **consumer** pipeline of OTS proofs.
- Treat the stationary calendar as a **future enhancement**, not a
  prerequisite for correctness.

### Why still keep the `ots/calendar` sidecar and `ots-cal` env?

The sidecar and env are useful even without a real calendar server because
they:

- Validate that the `opentimestamps` and `opentimestamps-client` toolchain
  works in a containerized environment similar to CI runners.
- Provide a deterministic place to exercise OTS integration tests without
  hitting public calendars on every run.
- Set up a ready-made anchor point (port, container, workflow) for a future
  real calendar implementation.

This aligns with ADR-014's intent to reduce external flakiness, while
acknowledging that the *server* side is currently stubbed.

## Implications

- **Documentation**

  - ADR-014 remains valid as a direction but should be read together with
    this ADR: ADR-014 is about *intent*; ADR-020 is about the *current
    implementation reality*.
  - The README / `docs/ots-verification.md` should reference that the
    `ots-cal` env runs against an internal OTS toolchain sidecar rather
    than a full calendar.

- **Testing and CI**

  - `ots-cal` is a smoke/integration env for the OTS toolchain; it is not a
    conformance test of an internal calendar protocol.
  - Real OTS behavior (including `ots upgrade` and Bitcoin anchoring) is
    still verified via tests that talk to public calendars and/or the
    production pipeline.

- **Future Work**

  - If/when we decide to host our own calendar, we will:
    - Either adopt an upstream OTS calendar implementation, or
    - Specify and implement a minimal HTTP calendar API tailored to our
      needs (with clear alignment to ADR-015 for multi-anchor scenarios).
    - Replace the current `run_calendar.py` in `docker/calendar/` with a
      real server entrypoint and add protocol-level tests to validate the
      calendar's behavior.
  - That decision will likely warrant its own ADR (or an update to this
    one) once we select a concrete implementation path.

## Rollout & Migration

- **Now**

  - Keep using public calendars for production OTS proofs.
  - Use `ots-cal` + `ots/calendar` as a sidecar-based integration check for
    OTS tooling inside CI.
  - Treat `RUN_REAL_OTS=1` in `ots-cal` as a client-path exercise only; the
    local sidecar remains a health/tooling endpoint until a real calendar is
    implemented.

- **Later**

  - When we are ready to prototype an internal calendar, use the existing
    `ots-calendar` port mapping, tox env, and workflow as the
    test/deployment harness.
  - Gradually transition `ots-cal` from "stub/sidecar" to "real calendar
    conformance" by replacing the sidecar with an actual OTS-compatible
    calendar service and expanding the protocol-level test suite under the
    `real_ots` marker.

## External References

- OpenTimestamps project: https://opentimestamps.org/ and
  https://github.com/opentimestamps
