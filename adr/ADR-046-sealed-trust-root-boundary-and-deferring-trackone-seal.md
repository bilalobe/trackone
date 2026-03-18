# ADR-046: Sealed trust-root boundary and deferring a dedicated `trackone-seal` crate

**Status**: Accepted
**Date**: 2026-03-18

## Related ADRs

- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md): Rust/PyO3 boundary strategy
- [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md): trust and verification boundary discipline
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md): authoritative artifact and digest contract
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md): verification/disclosure bundle semantics
- [ADR-043](ADR-043-phased-bundle-manifest-maturity-for-id.md): manifest maturity and publication packaging
- [ADR-044](ADR-044-json-schema-modularity-and-authoritative-contract-artifacts.md): authoritative machine-readable contracts
- [ADR-045](ADR-045-git-signed-evidence-distribution-plane.md): publication/distribution boundary for small authoritative artifacts

## Context

TrackOne's highest-value integrity risks in the current runtime pipeline are not
primarily remote API attacks. They are local trust-root drift and partial
tampering across the operator-controlled ingest and publication path.

The concrete pressure points are:

- `device_table.json`, which influences replay acceptance and device-facing
  runtime key state;
- `provisioning/authoritative-input.json`, which carries authoritative
  identity/deployment input for the current run;
- the verifier-facing `day/<date>.verify.json`, which binds artifact digests and
  disclosure state; and
- the export/publication gate, which must refuse to publish if the current
  verifier-visible state no longer matches what was exercised.

Recent `alpha.11` hardening made this boundary more explicit:

- trust-root input files now require detached SHA-256 sidecars;
- digest generation and `hex64` normalization moved into the native
  `trackone_core.ledger` surface;
- verifier-visible manifests now carry the authoritative artifact/digest view;
  and
- export reruns a fresh local verification gate before publication.

Internally, this integrity-control envelope has been referred to as the
`keylock bracket`: trusted input state is sealed before use, the exact sealed
state is bound into verifier-visible evidence, and publication is refused if
that bound state changes.

That concept is useful, but it creates a design question:

- should the seal boundary become a dedicated Rust crate such as
  `trackone-seal`; or
- should the primitive pieces stay in `trackone-ledger` while workflow policy
  stays in Python?

Today the implementation is still mixed:

- `trackone-ledger` owns deterministic digest/normalization primitives;
- `trackone-gateway` / `trackone_core` expose those primitives to Python through
  PyO3; and
- Python orchestration owns file lifecycle, manifest assembly, verification
  gating, and export/publication policy.

The risk in splitting too early is creating a thin crate wrapper around SHA-256,
sidecar parsing, and manifest choreography without a stable reusable domain
model.

## Decision

### TrackOne adopts a sealed trust-root boundary as an explicit integrity control

TrackOne treats the trust-root input and publication path as one bounded
integrity surface.

That boundary currently covers:

- `device_table.json`;
- `provisioning/authoritative-input.json`;
- verifier-facing artifact/digest binding in `day/<date>.verify.json`; and
- fresh local verification before export/publication.

The governing invariant is:

1. trust-root input state is sealed before use;
1. the exact sealed state is bound into verifier-visible evidence; and
1. publication is refused if the current state no longer matches the bound
   state.

### The sealed trust-root boundary does not become a dedicated crate yet

TrackOne does **not** create a `trackone-seal` crate at this time.

The current boundary is accepted as a design concept and control surface, but
the crate boundary is not yet stable enough to justify a separate package.

### Primitive seal helpers stay in `trackone-ledger`

Low-level deterministic helpers that are part of the seal contract belong in
`trackone-ledger`.

That includes, for example:

- canonical SHA-256 hex generation;
- `hex64` normalization and validation; and
- future deterministic seal-state primitives that are independent of Python
  workflow policy.

### Python/native exposure stays in `trackone-gateway` / `trackone_core`

If Python-facing ingest, verifier, or export code needs the seal primitives, the
binding layer belongs in `trackone-gateway` and is surfaced through
`trackone_core`.

This preserves the ADR-017 split:

- stable primitive logic in Rust;
- workflow-facing access via PyO3;
- orchestration and policy kept outside the primitive crate.

### File lifecycle and publication policy stay in Python

The following remain Python responsibilities:

- sidecar file lifecycle;
- trust-root input snapshot/choreography;
- verification-manifest assembly;
- local verification-gate enforcement; and
- export/publication refusal policy.

These behaviors are workflow and operator-policy concerns, not yet a stable
reusable Rust artifact model.

### `keylock bracket` is an internal design term, not standards language

The `keylock bracket` label MAY be used in internal threat-model and
architecture discussion.

It SHOULD NOT be promoted into the Internet-Draft or other standards-facing
material as normative terminology. External-facing text should use plainer terms
such as:

- sealed trust-root inputs;
- bound input-state verification; or
- input-state integrity envelope.

### A future `trackone-seal` crate requires a stable reusable sealed-state model

TrackOne will create a dedicated crate only if the seal boundary becomes a real
artifact family rather than a handful of helpers plus workflow rules.

That threshold is met only if all of the following become true:

- sealed-input objects are defined as stable first-class types rather than ad
  hoc sidecars;
- multiple consumers need the same semantics across ingest, verification,
  export, and publication/transparency tooling; and
- the domain is coherent enough to own reusable operations such as:
  - `SealedInputRef`;
  - `SealSet`;
  - manifest-binding helpers; and
  - verification of sealed input state across exported bundle boundaries.

Until those conditions are met, TrackOne keeps the seal contract split across
`trackone-ledger`, `trackone-gateway`, and Python orchestration.

## Consequences

### Positive

- Gives the threat model and implementation a single named integrity boundary
  around mutable trust-root state and publication gating.
- Avoids premature crate proliferation and a weak package boundary.
- Keeps deterministic primitives single-sourced in Rust while preserving Python
  control of workflow policy.
- Makes future refactoring easier because the condition for a new crate is now
  explicit instead of implicit.
- Reduces the risk of treating mutable local runtime state as if it were already
  a stable signed artifact family.

### Negative

- The seal boundary remains partly conceptual and partly operational rather than
  embodied in one library surface.
- Python still owns important security-relevant choreography around sidecars,
  manifests, and export gates.
- The current sidecar-based seal is tamper-evident and drift-detecting, not a
  separate trust root against full host compromise.

### Neutral / clarified

- This ADR does not weaken artifact authority decisions in ADR-039.
- This ADR does not change publication semantics from ADR-043 or ADR-045; it
  clarifies what input state must remain bound and stable before publication.
- This ADR does not require signatures on mutable local state. The current
  problem is state-integrity control inside one trust domain, not external
  issuance semantics.

## Alternatives considered

### Create `trackone-seal` now

Rejected for now.

This would likely produce a crate whose real contents were:

- SHA-256 helpers already appropriate for `trackone-ledger`;
- sidecar parsing tightly coupled to the current Python workflow; and
- manifest/publication logic that is not stable enough to become a reusable Rust
  domain.

That would create one more package boundary without a strong independent model.

### Keep the current behavior without naming the boundary

Rejected.

Without an explicit decision, the repo would continue to accumulate security
controls around the trust-root inputs and publication gate without a clear
shared model for why those controls belong together.

### Move the entire seal path into Rust immediately

Rejected for now.

The current pressure is not a lack of performance. It is a need for clear
boundary ownership. Moving file choreography, manifest assembly, and export
policy wholesale into Rust now would increase implementation weight before the
artifact model is stable.

## Implementation notes

Use the following placement rule for new work:

- deterministic digest, normalization, or reusable seal-state logic belongs in
  `trackone-ledger`;
- Python-facing exposure of that logic belongs in `trackone-gateway` /
  `trackone_core`;
- file lifecycle, manifest assembly, verification gating, and publication policy
  stay in Python; and
- only create `trackone-seal` once sealed-state objects and operations are
  stable enough to be reused independently of the current Python workflow.
