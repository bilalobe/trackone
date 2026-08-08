# ADR-061: Library and Application Package Boundaries

**Status**: Accepted
**Date**: 2026-07-15
**Amended**: 2026-08-08

## Related ADRs

- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md): historical PyO3 integration path
- [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md): coordinated workspace releases
- [ADR-038](ADR-038-surface-tooling-and-abi3-wheel-strategy.md): historical wheel boundary
- [ADR-046](ADR-046-sealed-trust-root-boundary-and-deferring-trackone-seal.md): deterministic seal and publication boundaries
- [ADR-051](ADR-051-internal-dependency-boundaries-and-feature-demotion.md): dependency direction and feature demotion
- [ADR-059](ADR-059-rust-native-conformance-archive-and-workflow-lanes.md): release conformance packaging

## Context

The former `trackone-gateway` package combined four independently changing
concerns:

- reusable OTS proof and metadata verification;
- a durable HTTP/PostgreSQL service runtime and its migrations;
- optional PyO3 conversion and module-registration code; and
- a library target named `trackone`, which obscured the package identity.

The evidence verifier depended on that mixed package only to reach OTS
verification. Service features pulled application dependencies into the same
manifest as the optional binding, and deployment assets had no source-level
owner. Large single-file ingest and evidence implementations further hid
otherwise sound internal boundaries.

## Decision

The workspace uses two explicit source layers:

1. `crates/` contains reusable domain libraries only.
2. `apps/` contains deployable or operator-facing application packages.

The concrete allocation is:

- `trackone-ots` owns native OTS parsing, verification, and sidecar binding;
- `trackone-gateway-svc` owns the v2 producer, PostgreSQL store, HTTP service,
  RFC 3161 submission, service binary, migrations, Dockerfile, Helm chart, and
  build-only local Kustomize assets; Helm is the sole runtime deployment
  surface;
- `trackone-evidence` is the supported v2 verifier/compactor library and CLI
  but lives under `apps/` and depends directly on `trackone-ots`;
- the mixed `trackone-gateway` package and its mismatched `trackone` library
  target are removed.

Reusable crates may depend only on other reusable crates. Applications may
compose reusable crates.

`trackone-ingest` exposes its existing crate-root API from internal
`profile`, `frame`, `aad`, `nonce`, `fixture`, `replay`, and
`admission` modules. The evidence library exposes its forward-only v2
verification and compaction surface from the `v2` module. Its former v1
verification/export modules and compatibility command names are removed.

The coordinated release contains eight reusable libraries and two publishable
applications. The legacy `trackone-python` PyO3 leaf is removed; Python
remains only for repository tooling and detached verification.

This ADR supersedes the package-allocation parts of ADR-051 and the
`trackone-gateway` Python-exposure statements in ADR-046. Their protocol and
dependency-direction decisions remain in force.

## Consequences

### Positive

- Evidence no longer depends upward on a service or binding package.
- The deployable service has one manifest, binary, migration owner, and deploy
  subtree.
- Package names and Rust import names are aligned.
- Feature unification can no longer combine service and binding concerns in one
  package.
- Internal module boundaries reduce contributor load without expanding the
  public crate surface unnecessarily.

### Negative

- Rust callers of the former `trackone::ots` and `trackone::v2_*` paths must
  migrate to `trackone_ots` and `trackone_gateway_svc`.
- Release automation and downstream package-count assumptions must recognize
  nine publishable packages.
- Historical ADRs and changelogs retain references to the former package name;
  readers must follow this ADR for the current allocation.

## Alternatives Considered

- Keep a compatibility `trackone-gateway` façade. Rejected because no cohesive
  reusable gateway implementation remained after moving OTS, service, and
  binding concerns.
- Add more features to the old package. Rejected because additive Cargo feature
  unification does not express mutually exclusive application ownership.
- Retain the legacy Python leaf. Rejected after the Rust-native applications
  and reusable crates became the supported product surface.

## Testing & Migration

1. Check the full workspace and the no-std ingest base.
2. Test the supported `std,xchacha` ingest path.
3. Test the OTS, evidence, and gateway-service packages independently.
4. Run the curated workspace test, Clippy, format, and production-build gates.
5. Package the nine publishable packages, lint/package the app-owned Helm
   chart, and assemble the conformance archive.
6. Verify searches and Cargo metadata show no dependency on the removed
   `trackone-gateway` package.
7. Run `just boundaries` so layer direction and Cargo library-target naming
   remain checked in CI.
