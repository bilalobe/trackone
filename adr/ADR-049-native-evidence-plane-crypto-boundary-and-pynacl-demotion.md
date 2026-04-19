# ADR-049: Native Evidence-Plane Crypto Boundary and PyNaCl Demotion

**Status**: Accepted
**Date**: 2026-04-19
**Supersedes**: [ADR-005](ADR-005-pynacl-migration.md)

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): cryptographic
  primitives and framing
- [ADR-002](ADR-002-telemetry-framing-and-replay-policy.md): telemetry framing
  and replay policy
- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md): Rust core and PyO3
  integration strategy
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md):
  transport versus commitment serialization boundaries
- [ADR-038](ADR-038-surface-tooling-and-abi3-wheel-strategy.md): surface tooling
  and abi3 wheel strategy
- [ADR-039](ADR-039-cbor-first-commitment-profile-and-artifact-authority.md):
  CBOR-first commitment authority
- [ADR-047](ADR-047-trackone-evidence-plane-within-device-lifecycle.md):
  TrackOne as the evidence plane within a broader device lifecycle system

## Context

ADR-005 was the right decision for the earlier Python-first implementation. It
removed a mixed `cryptography` plus `pynacl` dependency split and made PyNaCl the
single Python crypto implementation. That reduced dependency sprawl while the
gateway verifier, pod simulator, deterministic vectors, and signature helpers
were primarily Python-owned.

The repository has since moved the evidence-plane authority boundary:

- supported framed ingest is `rust-postcard-v1`;
- framed material validation, XChaCha20-Poly1305 decrypt, postcard `Fact`
  decode, replay admission, and accepted-fact construction are owned by
  `trackone_core.crypto`;
- canonical fact/day CBOR, digest normalization, and Merkle behavior are owned
  by `trackone_core.ledger` and `trackone_core.merkle`; and
- Python scripts increasingly orchestrate workflow steps rather than define
  protocol-critical bytes.

ADR-047 also narrows TrackOne's role: TrackOne is the evidence plane, not the
entire device lifecycle or control plane. The same boundary should apply to
runtime dependencies. A broad Python crypto dependency should not become the
primary source of truth for evidence-plane admission or commitment behavior when
the stable native module already owns those operations.

Keeping PyNaCl as a base dependency now creates the wrong incentive. It makes it
easy for Python helper code to grow into a second protocol implementation, and it
blurs whether `trackone_core` or `scripts/` is the stable source module for
framed admission and evidence generation.

## Decision

### 1. `trackone_core` is the stable evidence-plane source module

For supported evidence-plane runtime behavior, Python callers should use the
stable `trackone_core` package surface backed by the native extension.

The authoritative surfaces are:

- `trackone_core.crypto` for supported framed admission, native replay state,
  decrypt/material validation, postcard `Fact` plaintext handling, and accepted
  fact construction;
- `trackone_core.ledger` for canonical CBOR, digest normalization, and day
  artifact helpers;
- `trackone_core.merkle` for Merkle root recomputation; and
- `trackone_core.release`, `trackone_core.verification`, and
  `trackone_core.sensorthings` for shared report, manifest, disclosure, and
  projection-domain helpers where they exist.

### 2. Python `scripts/` remain surface tooling

Python scripts remain important, but their role is orchestration:

- command-line ergonomics;
- file layout and local workflow composition;
- optional anchoring channel orchestration;
- schema/report assembly;
- evidence export choreography; and
- demo/test workflow composition.

Scripts MUST NOT become the sole implementation of supported framed admission,
canonical commitment bytes, digest normalization, or Merkle semantics.

### 3. PyNaCl is demoted from primary runtime dependency

PyNaCl is no longer the primary implementation dependency for TrackOne's
evidence-plane runtime.

PyNaCl MAY remain available for:

- optional peer-signature tooling until native Ed25519 signing/verification is
  exposed through `trackone_core`;
- legacy or historical crypto-vector generation and parity checks;
- development-only tests that intentionally compare against libsodium; and
- isolated lifecycle/control-plane integration helpers that are outside the
  evidence-plane authority boundary.

PyNaCl MUST NOT be required for:

- `rust-postcard-v1` framed ingest;
- canonical fact/day CBOR generation;
- day-root or Merkle recomputation;
- verifier-facing manifest validation; or
- normal evidence export gates.

### 4. `crypto_utils.py` is legacy/dev/test helper code

The Python module `scripts/gateway/crypto_utils.py` remains historical helper
code unless and until it is replaced or retired. New supported evidence-plane
runtime code should not depend on it for authoritative behavior.

If a Python crypto helper is still useful for tests, vector regeneration, or
optional integrations, its scope should be labeled explicitly as dev/test or
optional tooling.

### 5. Dependency packaging follows the authority boundary

A follow-up implementation change SHOULD move PyNaCl out of the base
`project.dependencies` set and into explicit optional extras, for example:

- a peer-signature or optional-channel extra for `peer_attestation.py`;
- a dev/test extra for historical vector checks; and
- any lifecycle/control-plane extra that intentionally opts into PyNaCl-backed
  Python crypto outside the evidence-plane core.

The base install should remain centered on the packaged `trackone_core` wheel and
the pure-Python shims that expose it.

### 6. Critical paths fail closed when native authority is unavailable

For supported evidence-plane runtime paths, missing native authority is a
configuration error, not a reason to fall back to Python crypto.

Acceptable behavior:

- fail closed for authoritative framed admission, commitment CBOR, digest
  normalization, Merkle recomputation, and export verification gates; and
- report optional channels such as peer signatures as missing/skipped/failed
  according to the configured policy.

## Consequences

### Positive

- Keeps TrackOne aligned with ADR-047: the evidence plane has a narrow,
  defensible runtime boundary.
- Makes `trackone_core` the obvious stable import surface for downstream Python
  callers.
- Reduces the chance that Python helper code recreates wire/admission semantics
  independently.
- Allows PyNaCl to remain useful without making it a base runtime dependency.
- Supports a centralized milestone PR: the dependency demotion, framed fixture
  cleanup, and Postcard/CBOR contract clarification can be reviewed as one
  coherent boundary change.

### Neutral

- Existing PyNaCl-backed tests and optional peer-attestation helpers can remain
  during migration.
- Some historical ADR text and vector-generation tooling will continue to refer
  to PyNaCl as a comparison implementation unless updated separately.
- The first PR that moves PyNaCl out of base dependencies will update
  `pyproject.toml`, `uv.lock`, and the relevant tox/test extras.

### Negative / Tradeoffs

- Environments without a working `trackone_core` native extension can no longer
  expect Python crypto fallback behavior for supported evidence-plane runtime
  paths.
- Optional peer signatures still need a dependency story until native Ed25519 is
  exposed or another explicit optional implementation is selected.
- The project must be stricter in review: new Python crypto code needs a clear
  reason and scope label.

## Migration Plan

1. Mark ADR-005 as superseded by this ADR.
1. Keep current code behavior while the tree is already consolidating
   `rust-postcard-v1`, CBOR authority, and Rust framed fixture emission.
1. Move PyNaCl from base dependencies into explicit optional extras.
1. Update tests and benchmarks so supported framed fixtures come from the Rust
   framed fixture emitter instead of PyNaCl/TLV helpers.
1. Add or keep smoke tests proving normal framed/evidence paths import and run
   without `nacl` installed when peer signing is disabled.
1. Decide whether peer-signature generation and verification should move into
   `trackone_core` or remain an optional publication-channel helper.
1. Retire or relabel `scripts/gateway/crypto_utils.py` once no supported runtime
   path imports it.

## Risk Assessment

Risk is low to neutral for a centralized milestone PR because the supported
framed/evidence path has already moved to native `trackone_core` authority. The
main risk is packaging and test-selection churn when PyNaCl leaves the base
dependency set. That risk is bounded by keeping PyNaCl in explicit extras during
the transition and by making optional peer-attestation behavior report
missing/skipped/failure states under existing policy handling.

## Alternatives Considered

### Keep PyNaCl as the primary Python runtime dependency

Rejected.

This preserves short-term convenience but weakens the boundary between
`trackone_core` authority and Python surface tooling. It also encourages future
runtime code to bypass the stable native module.

### Remove PyNaCl immediately from all code

Rejected for now.

Peer attestation, historical vector checks, and some dev/test helpers still use
PyNaCl. Removing it everywhere is unnecessary to close the evidence-plane
boundary and would increase migration risk without improving the supported
framed/commitment path.

### Make the native extension optional for supported evidence-plane runtime

Rejected.

Optional native authority reintroduces dual implementations for the same
protocol-critical behavior. For normal evidence-plane operation, failing closed
is clearer and safer.

## Status Rationale

Accepted because it reflects the current repository direction: Postcard remains
the Rust-native framed plaintext path, CBOR remains the commitment authority, and
`trackone_core` is the stable Python-facing module for evidence-plane authority.
ADR-005 remains useful historical context for the earlier Python-first phase but
no longer governs primary runtime dependency strategy.
