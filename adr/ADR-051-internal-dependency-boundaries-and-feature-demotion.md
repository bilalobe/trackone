# ADR-051: Internal Dependency Boundaries and Feature Demotion

**Status**: Accepted
**Date**: 2026-04-19

## Related ADRs

- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md): Rust core and PyO3
  integration strategy
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md):
  transport versus commitment encodings
- [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md):
  workspace versioning and release visibility
- [ADR-038](ADR-038-surface-tooling-and-abi3-wheel-strategy.md): surface
  tooling boundaries and abi3 wheel strategy
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md):
  CBOR-first commitment profile and artifact authority
- [ADR-049](ADR-049-native-evidence-plane-crypto-boundary-and-pynacl-demotion.md):
  native evidence-plane crypto boundary and PyNaCl demotion

## Context

The workspace layering has become clearer over time:

- `trackone-constants` holds dependency-free shared constants;
- `trackone-core` holds canonical fact and commitment semantics;
- `trackone-ingest` holds framed transport/admission behavior;
- `trackone-pod-fw` is the pod-side emitter/runtime helper;
- `trackone-gateway` is the host/Python adapter; and
- `trackone-ledger` owns day artifacts, hashing helpers, and Merkle/day-chain
  behavior.

During the current consolidation pass, the codebase still contained several
internal edges that reflected migration convenience more than stable ownership:

- `trackone-core` still carried ambient Postcard support and historical
  references that were not needed by commitment-only consumers;
- `trackone-ingest` defined a stable profile label that was really a
  dependency-free shared constant;
- `trackone-gateway` unconditionally pulled PyO3 even when compiling pure Rust
  helper code; and
- `serde-big-array` remained in the graph solely for one `[u8; 64]` field
  serializer shape.

Those edges were not protocol bugs, but they made the workspace harder to read
correctly:

- they made transport or host-binding concerns look more central than they are;
- they increased the chance that embedded or `no_std`-first consumers would drag
  in unnecessary dependencies; and
- they encouraged crate boundaries to follow old implementation accidents rather
  than current authority boundaries.

The repository also has an explicit promotion rule: do not create a new crate
or standards-facing surface unless there is a stable object model, more than
one real consumer or boundary, and a meaningful interoperability benefit. That
rule favors tightening internal feature and dependency boundaries before
splitting more crates.

## Decision

### 1. Internal dependency edges follow authority boundaries

Workspace dependency edges should reflect which crate owns a responsibility, not
which crate happened to implement it first during migration.

The intended ownership is:

- `trackone-constants`: dependency-free shared labels, lengths, and numeric
  limits;
- `trackone-core`: canonical fact model, canonical commitment inputs, and shared
  protocol semantics;
- `trackone-ingest`: framed transport profiles, admission/projection rules, and
  replay/admission policy types;
- `trackone-gateway`: host adapter and Python/native binding surface;
- `trackone-ledger`: day artifact helpers, hashing utilities, and
  Merkle/day-chain behavior; and
- `trackone-pod-fw`: pod-side emission helpers using ingest/core contracts.

### 2. Dependency-free shared identifiers belong in `trackone-constants`

If a value is stable, reused, dependency-free, and useful across more than one
crate, it should live in `trackone-constants` rather than in an operational
crate.

This includes stable labels such as the ingest profile identifier
`INGEST_PROFILE_RUST_POSTCARD_V1`.

`trackone-constants` remains intentionally narrow: values only, not parsers,
validators, serializers, or policy logic.

### 3. Transport support in `trackone-core` must be explicit and opt-in

`trackone-core` should stay "boring" for consumers that only need canonical
types, CBOR commitment helpers, or shared semantics.

Transport-specific support such as Postcard is allowed in `trackone-core` only
when it is clearly an internal transport helper and is exposed behind an
explicit non-default feature.

This means:

- commitment-only users of `trackone-core` must not pay for Postcard
  transitively; and
- the existence of a transport helper in `trackone-core` does not make that
  helper part of the commitment boundary described by ADR-034 and ADR-039.

### 4. Host-binding dependencies must remain leaf-scoped

Python/native binding dependencies such as PyO3 should remain confined to the
host adapter crate and must not leak into pod, ingest, core, or constants
consumers.

For `trackone-gateway`, that means:

- PyO3-facing functionality is behind an optional `python` feature;
- the default build may still enable that feature for wheel/build tooling
  compatibility; but
- `--no-default-features` must remove the PyO3 dependency path entirely for pure
  Rust consumers and checks.

Embedded-facing crates (`trackone-pod-fw`, `trackone-ingest`, `trackone-core`,
`trackone-constants`) must not depend on `trackone-gateway`.

### 5. Remove one-off compatibility dependencies when a local wire-compatible helper is clearer

If a dependency remains only to preserve a simple serialization shape for a
single field, prefer a small local helper when it preserves wire compatibility
and reduces workspace drag.

This applies to cases like replacing `serde-big-array` with a local
wire-compatible serializer for `[u8; 64]`.

The intent is not "rewrite every helper locally." The intent is to remove loose
single-purpose dependencies when the local replacement is smaller, clearer, and
does not widen authority.

### 6. Prefer feature gates over premature crate splits

When a module contains reusable pure Rust logic but currently has only one real
consumer boundary, the preferred first move is feature-gating host-only parts
rather than splitting a new crate immediately.

In practice, that means pure Rust logic currently living under
`trackone-gateway` may stay there until the promotion rule is actually met.

This keeps the workspace smaller while still allowing:

- pure Rust compilation paths without Python bindings; and
- later extraction if more than one stable consumer emerges.

## Consequences

### Positive

- Makes the dependency graph match the protocol and deployment boundaries more
  closely.
- Keeps embedded-facing builds free of PyO3 and other host-only dependencies.
- Reduces accidental coupling between commitment semantics and transport helpers.
- Shrinks the workspace graph by removing stale or one-off dependencies.
- Gives maintainers a repeatable rule for future cleanup: demote, gate, or
  relocate internal edges before proposing a new crate.

### Neutral

- Some crates now have a more explicit feature matrix, especially around
  transport helpers and Python bindings.
- Mixed modules may need `cfg` structure to keep pure Rust logic available while
  gating host-facing wrappers.
- This ADR records the boundary rule; specific cleanup PRs still carry the code
  churn and validation burden.

### Negative / Tradeoffs

- Feature-gating can make some module layouts slightly less direct than an
  unconditional build.
- The workspace now relies more on reviewers to notice when a "convenience"
  dependency is trying to become architectural.
- A later crate split may still be needed if a currently leaf-local module gains
  multiple stable consumers.

## Implementation Notes

This ADR records the pattern behind the current cleanup pass, including:

- removing stale core-side links that implied gateway/Merkle ownership in the
  wrong place;
- promoting stable ingest profile labels into `trackone-constants`;
- gating Postcard support in `trackone-core` behind an explicit feature;
- removing `serde-big-array` in favor of a local wire-compatible helper; and
- making the PyO3 surface in `trackone-gateway` optional so pure Rust builds can
  compile without Python bindings.

These examples are illustrative, not exhaustive. Future dependency cleanup
should follow the same boundary logic even when the concrete crates differ.

## Risk Assessment

Risk is low to moderate.

The policy mostly affects internal dependency shape, not external protocol
behavior. The main risks are feature-matrix regressions and accidentally
changing serialization shape while trimming dependencies. Those risks are
bounded by keeping behavior-preserving compatibility tests in place and by
treating wire format preservation as non-negotiable when replacing helper
dependencies.

## Alternatives Considered

### Keep convenience dependencies in place

Rejected.

This avoids short-term churn but keeps migration leftovers looking like stable
architecture. It also makes it easier for embedded or commitment-only consumers
to inherit dependencies they do not actually need.

### Split new crates immediately for every reusable helper cluster

Rejected for now.

That would overfit the current implementation and violate the repository's
promotion rule when there is still only one real consumer boundary.

### Move more transport or host logic into `trackone-core`

Rejected.

That would flatten the very boundary this cleanup is trying to protect.
`trackone-core` should remain the canonical substrate, not the catch-all crate
for every useful helper.
