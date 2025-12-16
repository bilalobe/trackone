# ADR-022: First-party stationary OTS calendar service in CI

**Status**: Proposed
**Date**: 2025-11-28
**Related ADRs**:

- ADR-003: Merkle canonicalization and OTS anchoring
- ADR-007: OTS CI verification and Bitcoin headers
- ADR-008: M4 completion OTS workflow
- ADR-014: Stationary OTS calendar (original concept)
- ADR-015: Parallel RFC 3161 anchoring
- ADR-020: Stationary OTS calendar follow-up (clarification)
- ADR-021: Safety-net OTS pipeline verification (requirements)
- ADR-024: Anti-replay and OTS-backed ledger (operational semantics)
- ADR-030: EnvFact schema and duty-cycled day.bin anchoring

## Context

We currently rely on:

- **Public OpenTimestamps (OTS) calendars** for real Bitcoin-anchored proofs in production (per ADR-003, ADR-007, ADR-008).
- A **stationary/calendar concept** (ADR-014) to reduce external dependency and flakiness.
- A **Docker-based sidecar** under `docker/calendar/` and a `tox -e ots-cal` environment (ADR-020) that:
  - Runs OTS tooling inside a container.
  - Exposes port `8468` as a placeholder.
  - Does **not** implement a real OpenTimestamps HTTP calendar protocol or persist Merkle / anchoring state.

This gives us:

- Good coverage of the **client side** (toolchain, CLI wiring, environment variables like `OTS_CALENDARS`).
- No end-to-end testing against a **first-party HTTP calendar** that:
  - Accepts timestamp requests over a stable API.
  - Persists state and upgrades proofs in a controlled environment.
  - Can be exercised reliably from CI and dev tox envs without hitting public pools.

Constraints and related context:

- **CI / tox layout**
  - `ots` / `slow` envs: real OTS integration (when `RUN_REAL_OTS=1`), still talking to public calendars.
  - `ots-cal` env: smoke/integration env targeted at the sidecar, with `RUN_REAL_OTS=0` (per ADR-020).
- **Workflow expectations**
  - ADR-014 originally envisioned a "stationary" calendar primarily for CI and reproducibility, not necessarily a public internet service.
  - ADR-015 adds parallel RFC 3161 anchoring, so OTS is one of several anchoring channels; we must not introduce calendar changes that break that alignment.
- **Safety and correctness**
  - ADR-021 classifies misbehaving calendars / misconfigured `OTS_CALENDARS` as `M → H` impact risks.
  - We want more realistic behavior than a pure stub, but we also want to avoid over-committing to a fully-featured, long-lived, Bitcoin-anchoring server we must operate as critical infra.

We need to clarify what "first-party stationary calendar" means **for this project**, and how far we intend to go in scope.

## Problem

Today, we have an **ambiguous calendar story**:

- ADR-014 suggests a self-hosted calendar service, but ADR-020 clarifies we only built a **tooling sidecar**, not a real HTTP calendar implementation.
- CI and tox environments (`ots-cal`) do not exercise:
  - Actual OpenTimestamps calendar protocol behavior.
  - Proof upgrade flows that depend on a long-lived calendar state we control.
- Production remains tied to **public calendars** for real anchoring. There is:
  - No well-defined first-party calendar API for this repository.
  - No clear plan for when or whether we will own calendar anchoring responsibilities.

This leads to risks:

- **Misinterpretation**: Stakeholders may assume "we host our own calendar" because ADR-014 mentions a stationary calendar, while ADR-020 only partially corrects this.
- **Test coverage gaps**: We cannot run realistic end-to-end tests for:
  - Client ↔ calendar HTTP protocol behavior.
  - Failover between a first-party calendar and public pools.
- **Ops uncertainty**: It is unclear whether we intend to:
  - Ultimately deploy a real HTTP calendar with Bitcoin anchoring duties, or
  - Stay permanently on public calendars while only maintaining a richer stub for CI.

We need a concrete, scoped decision about:

1. **What kind of first-party calendar we build** (full implementation vs "realistic stub").
1. **Where it runs** (Docker sidecar, local dev service, optional production/staging).
1. **How it integrates with CI/tox and `OTS_CALENDARS`**.
1. **How we migrate without breaking existing OTS flows and ADR-015's multi-anchor assumptions.**

## Decision

We will:

1. **Define a first-party HTTP "stationary calendar" for CI/dev, with limited scope**

   - Implement a **first-party HTTP service** in this repo that:
     - Speaks a minimal, well-documented OTS-compatible calendar API (or a thin wrapper over an upstream implementation).
     - Handles timestamp requests and returns OTS responses for CI/dev workloads.
     - Persists calendar state locally (within a Docker volume or temp directory) across the lifetime of the CI job or local session.
   - Treat this as a **deterministic, test-oriented calendar**:
     - Optimized for reproducible integration tests.
     - Not initially responsible for production-grade Bitcoin anchoring.

1. **Anchor this service in `docker/calendar/` and the `ots-cal` tox env**

   - Replace the current "tooling sidecar only" container with:
     - A container image that runs the new HTTP calendar service by default.
     - An entrypoint compatible with `tox -e ots-cal` and CI workflows.
   - Keep `ots-cal` focused on:
     - Exercising client ↔ calendar HTTP interactions.
     - Validating calendar selection behavior (`OTS_CALENDARS` ordering).
     - Running a targeted subset of tests that depend on a live calendar.

1. **Preserve production anchoring on public calendars for now**

   - Continue to use public calendars (as in ADR-008) for:
     - Real production OTS proofs.
     - Long-term Bitcoin anchoring.
   - The first-party calendar is **not a production anchoring authority** in this ADR.
     - It may forward to public calendars behind the scenes or operate in a "stub-but-realistic" mode.
     - It must not be treated as the sole source of truth for production attestations.

1. **Align with safety-net assumptions from ADR-021**

   - Make calendar selection and behavior **explicit and observable**:
     - Log which calendar endpoints are used for CI/dev vs production.
     - Ensure mis-configuration falls back safely (fail closed in verification where appropriate).
   - Use the first-party calendar to:
     - Reduce CI flakiness.
     - Improve coverage of calendar-related error paths.
     - Not to weaken production trust or obscure failures.

1. **Document clear scope boundaries and future upgrade options**

   - This ADR **does not** commit us to:
     - Operating a 24/7, internet-facing OpenTimestamps calendar.
     - Replacing public calendars for mainnet Bitcoin anchoring.
   - It establishes:
     - A minimal, CI-focused HTTP calendar.
     - A migration path to either:
       - A full, production-grade calendar implementation (future ADR), or
       - A permanently stubbed/test-only calendar, with clear documentation.

## Scope

### In scope

- **CI / tox integration**:

  - `tox -e ots-cal`:
    - Starts and stops the first-party calendar as part of the test env.
    - Targets that calendar by default via `OTS_CALENDARS`.
  - GitHub Actions workflow:
    - Optionally uses the calendar container as a service for OTS-related integration jobs.

- **HTTP calendar service behavior (minimal feature set)**:

  - A well-defined subset of the OTS calendar protocol or a stable internal API that:
    - Accepts timestamp requests for test artifacts.
    - Stores enough state to serve upgrade/verification requests within the job's lifetime.
    - Optionally proxies or batches to public calendars to obtain real anchors.

- **Configuration and selection**:

  - `OTS_CALENDARS`:
    - CI: first-party calendar first, then public pools as fallback if needed.
    - Dev: configurable via env or config file.
  - Clear separation of endpoints for:
    - `ots-cal` (local/sidecar).
    - Real OTS tests (public calendars; `RUN_REAL_OTS=1`).

- **Logging and observability** (aligned with ADR-021):

  - Minimal structured logs for:
    - Incoming timestamp/upgrade requests.
    - Calendar endpoint selections.
    - Errors and retries.

### Out of scope (for this ADR)

- Operating a **production** stationary calendar that:
  - Anchors to Bitcoin on behalf of external users.
  - Offers an SLA or public interface beyond CI/dev needs.
- Redesigning the overall OTS anchoring model:
  - ADR-003 canonicalization and ADR-015 parallel anchoring remain unchanged.
- Replacing or deprecating public calendars in current production flows.

## Alternatives Considered

1. **Continue with public calendars only (status quo)**

   - Pros:
     - No new service to maintain.
     - Keeps this project strictly as an OTS client.
   - Cons:
     - CI and local tests remain sensitive to:
       - Public calendar availability and latency.
       - Changes outside our control.
     - No coverage for client ↔ calendar HTTP protocol quirks in a controlled environment.
   - Rejected because:
     - We want more deterministic CI behavior and better integration coverage.

1. **Keep the existing sidecar stub forever (no HTTP service)**

   - Pros:
     - Very low complexity; only exercises OTS CLI/tooling.
   - Cons:
     - Still no real HTTP service:
       - Cannot test calendar protocol behavior.
       - No way to validate `OTS_CALENDARS` selection against a controlled endpoint.
   - Rejected because:
     - It leaves the calendar story half-finished and confusing relative to ADR-014/020.

1. **Immediately build a full production-grade OTS calendar**

   - Pros:
     - Maximum control over anchoring lifecycle.
     - Potential to reduce reliance on public calendars entirely.
   - Cons:
     - High implementation and operational cost.
     - Requires taking on Bitcoin anchoring responsibilities (persistence, batching, security, monitoring).
     - Overlaps heavily with the upstream OTS ecosystem.
   - Rejected for now:
     - Misaligned with current priorities (client/pipeline robustness and multi-anchor support).
     - Better to stage via a CI-focused calendar and revisit production ownership later.

1. **Skip CI calendar tests entirely (mock everything)**

   - Pros:
     - Fastest, simplest: no network-bound tests at all.
   - Cons:
     - Poor realism; diverges from production behavior.
     - Hidden risks in configuration, calendar selection, and protocol interactions.
   - Rejected because:
     - ADR-008, ADR-014, ADR-021 all emphasize realistic OTS integration and safety.

1. **Alternative anchoring mechanisms only (e.g., Monero, L2-only)**

   - Pros:
     - Could reduce Bitcoin-specific dependencies.
   - Cons:
     - Orthogonal to the calendar question.
     - ADR-015 already covers *parallel* anchoring; removing OTS would conflict with core design.
   - Not chosen:
     - May be revisited in future ADRs but does not address the stationary calendar gap documented here.

## Technical Plan (high-level)

1. **Calendar service design**

   - Choose one of:

     - **Upstream-based**:
       - Wrap a reference OTS calendar implementation in a Docker image and configure it for CI/dev.
     - **Minimal internal API**:
       - Implement a narrow HTTP service with endpoints for:
         - `POST /stamp` (accept timestamps and return partial proofs or receipts).
         - `GET /upgrade/<id>` (simulate or proxy proof upgrades).
       - Optionally proxy to public calendars to obtain real anchors.

   - Requirements:

     - Deterministic behavior within CI jobs (no unbounded background upgrade tasks).
     - Uses the same `opentimestamps`/`opentimestamps-client` libraries we already vend.

1. **Docker and tox integration**

   - Update `docker/calendar/`:
     - Replace the current sidecar entrypoint with the new HTTP service entrypoint.
     - Ensure port mapping (e.g. `8468`) remains the same for continuity.
   - Update `tox.ini`:
     - Ensure `ots-cal`:
       - Starts the calendar container (or local service) in setup/teardown hooks.
       - Sets `OTS_CALENDARS` to point to the local calendar URL.
     - Keep `RUN_REAL_OTS=0` in `ots-cal` to avoid long-running real Bitcoin anchoring steps.

1. **CI workflow updates**

   - `ots-cal` GitHub Actions job:
     - Use the updated calendar container as a service.
     - Run a focused subset of tests that:
       - Exercise stamping/upgrade through the first-party calendar.
       - Validate error handling when the calendar is down or misconfigured.
   - Keep separate jobs for:
     - Real OTS integration (`RUN_REAL_OTS=1`, public calendars).
     - Safety-net checks per ADR-021.

1. **Configuration and safety controls**

   - Standardize config on:
     - `OTS_CALENDARS` env var for clients.
   - Add:
     - Logging of used calendar URLs.
     - Basic metrics (counts of requests, failures) when running in CI.

1. **Documentation**

   - Update:
     - `docs/ots-verification.md` to explain the role of the first-party calendar in CI/dev and how to run `tox -e ots-cal` locally.
   - Cross-link:
     - ADR-014 and ADR-020 (concept and follow-up).
     - ADR-021 (safety-net assumptions for calendar behavior).

## Migration Plan

1. **Phase 0 – Clarify expectations (this ADR)**

   - Adopt ADR-022 to:
     - Document the goal and scope of a first-party calendar.
     - Make it clear that production still relies on public calendars.

1. **Phase 1 – Prototype calendar service in `docker/calendar/`**

   - Implement the minimal HTTP service.
   - Test locally via:
     - `docker run` or an equivalent container runtime.
     - Manual client calls using existing OTS tooling with `OTS_CALENDARS` pointing to `localhost:8468`.

1. **Phase 2 – Wire into `tox -e ots-cal` and CI**

   - Update `tox.ini`:
     - `ots-cal`:
       - Starts the calendar container or local service.
       - Runs a subset of OTS-related tests against the calendar.
   - Update CI workflow:
     - Add/adjust job that:
       - Brings up the calendar service.
       - Runs `tox -e ots-cal`.
     - Ensure failing tests or calendar unavailability fails the job.

1. **Phase 3 – Expand test coverage**

   - Add / extend tests for:
     - Successful stamp/upgrade cycles against the first-party calendar.
     - Error/timeout paths when the calendar is down or misbehaving.
     - Correct fallback to public calendars when configured.
   - Ensure tests are aligned with ADR-021's safety-net goals.

1. **Phase 4 – Re-evaluate for production**

   - Once CI/dev usage is stable:
     - Decide whether to:
       - Promote the calendar to a **production** component with Bitcoin anchoring responsibilities, or
       - Keep it as a CI/dev-only tool and document that explicitly.
   - Any decision to use the first-party calendar in production would require:
     - A separate ADR (or major update to this one) covering:
       - Operational responsibilities.
       - Security and audit requirements.
       - Interaction with ADR-015's parallel anchoring (OTS + TSA + peers).

## Weekly ratchet automation

To satisfy ADR-001's M#5 "weekly ratcheting" key-rotation target, we are wiring the
first-party calendar into a dedicated GitHub Actions workflow (`Weekly Ratchet`)
that runs every Monday at 03:00 UTC (and on manual dispatch). The workflow:

- builds/boots the calendar sidecar, then runs `tox -e ots-cal`, `tox -e ots`, and
  `tox -e slow` with `RUN_REAL_OTS=1` and an explicit
  `OTS_CALENDARS="http://127.0.0.1:8468,https://a.pool.opentimestamps.org,https://b.pool.opentimestamps.org"`
  chain;
- fails fast if any tox env skips `real_ots` markers, if the required calendars are
  missing, or if `OTS_STATIONARY_STUB` drifts from the expected `0` real-calendar
  setting;
- emits a `ratchet.json` artifact describing timestamp, CI run ID, commit SHA,
  tox env outcomes, and the calendar configuration used; and
- on successful runs against `main`, creates an annotated tag in the semantic form
  `v0.0.1+N-m5`, where `N` increases monotonically with each ratchet.

### Operational guidance for long-term deployments

- **Anchor freshness:** Operators should watch for fresh `v0.0.1+N-m5` tags; if no new
  tag lands within the expected weekly window, schedule a manual rotation and
  investigate OTS/calendar health using the latest `ratchet.json` artifact.
- **Manual rotations:** When a manual rotation is required (e.g., air-gapped sites or
  maintenance windows), align it with the most recent ratchet tag to ensure the
  derived epoch matches the last CI-verified anchor, then resume automation so
  the next weekly tag reflects the updated state.
- **Verification:** During audits, retrieve the `ratchet.json` artifact (stored for at
  least two weeks) that corresponds to the tag anchoring the deployment. The
  artifact records the `RUN_REAL_OTS` and `OTS_CALENDARS` values exercised in CI,
  proving that anchors were produced with the agreed configuration.

This loop closes ADR-001's automation gap while grounding the weekly cadence in a
verifiable CI artifact + tag pair, so downstream schedulers can reason about
rotation freshness without querying internal logs.
