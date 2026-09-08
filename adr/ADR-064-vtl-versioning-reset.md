# ADR-064: VTL versioning reset and scoped archive claims

**Status:** Accepted
**Date:** 2026-08-27

> **Profile source (2026-09-06):** the active profile source is the
> [current VTL document on the IETF Datatracker](https://datatracker.ietf.org/doc/draft-elkhatabi-verifiable-telemetry-ledgers/).
> The repository does not track copies of the Internet-Draft. The checked-in
> CDDL, schemas, and vectors describe the bounded implementation surface.

## Context

The current profile defines the authoritative segment shape, assigns commitment profile
UUID `c08ade4e-1785-4eb6-9648-b7003d76288d`, restarts segment and evidence
schema counters at one, and defines a TSA-only baseline. Reusing the former
obsolete `v2` names, manifest versions, or an unscoped profile-conformance
archive claim would make incompatible artifacts appear continuous.

## Decision

- Expose profile code as `trackone_ledger::vtl` and
  `trackone_evidence::vtl`; do not retain version-named module shims.
- Accept and emit only producer manifest version 1. Verifier results use the
  unversioned shape and are identified by `verifier_policy_id`; former
  manifest v2/v3 inputs remain historical, not compatibility input.
- Implement the VTL segment, aligned batch, lifecycle, disclosure, chain, RFC
  3161 request/nonce, and future-skew rules under the normative UUID.
- Publish an unversioned conformance archive with claims limited to checks the detached
  runner mechanically replays. Do not describe implementation coverage as
  unscoped draft conformance.

The `/v2/records` and `/v2/record-batches` routes remain HTTP API-version
paths. They are not commitment-profile identifiers.

## Consequences

Existing segment and bundle artifacts from earlier profile revisions require
their historical software line. New deployments start a fresh ledger epoch and
database slate.
Release and survivability workflows publish the unversioned archive media type
`application/vnd.trackone.conformance.archive+tar`.

The precise current coverage boundary is maintained in
[`docs/conformance/vtl.md`](../docs/conformance/vtl.md).
