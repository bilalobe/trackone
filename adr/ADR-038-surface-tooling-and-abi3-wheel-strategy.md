# ADR-038: Surface Tooling Boundaries and `abi3` Wheel Strategy

**Status**: Accepted
**Date**: 2026-02-07

## Related ADRs

- [ADR-001](ADR-001-primitives-x25519-hkdf-xchacha.md): Cryptographic primitives (AEAD, Ed25519, HKDF)
- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Canonicalization/Merkle policy (protocol-critical)
- [ADR-013](ADR-013-python-version-support-policy.md): Python Version Support Policy (rolling three-minor window)
- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md): Rust Core + PyO3 integration (phased rollout)
- [ADR-034](ADR-034-serialization-boundaries-transport-vs-commitments.md): Serialization boundaries (transport vs commitment)
- [ADR-035](ADR-035-workspace-versioning-and-release-visibility.md): Workspace versioning and release visibility
- [ADR-037](ADR-037-signature-roles-and-verification-boundaries.md): Signature roles and verification boundaries

## Context

TrackOne is a mixed Rust/Python repository.

- **Rust crates** define protocol-critical behavior (canonicalization, hashing policy, ledger/stamping primitives,
  cryptographic operations).
- **Python** provides "surface tooling": operator ergonomics, pipeline orchestration, integration scripts, and
  test harnesses.
- A Rust extension built with PyO3/maturin provides a high-performance path for Python callers.

We want:

1. A durable, well-defined *boundary* between protocol-critical logic and surface tooling.
1. A packaging strategy that keeps the Python native module support burden reasonable as Python minors advance.
1. CI coverage that detects wheel regressions both in deterministic lockfile installs and in real-world pip resolution.

Terminology clarification:

- **OTS** in TrackOne means **OpenTimestamps**, not one-time signatures.

As of this writing:

- `requires-python = ">=3.12,<4.0"` in `pyproject.toml`.
- CI tests CPython 3.12, 3.13, and 3.14 (rolling window per ADR-013).
- PyO3 0.28 with `extension-module` feature; `abi3` feature not yet enabled.

## Decision

### 1. Define "surface tooling" as explicitly non-authoritative

Surface tooling includes:

- Python pipeline scripts under `scripts/` (batching orchestration, I/O, operators' CLI entry points).
- CI glue (tox envs, workflows, smoke tests).
- Convenience helpers (demo runners, local integration tooling).

Rules:

- Surface tooling **must not** become the *sole* source of truth for protocol-critical bytes.
- When protocol-critical encoding or hashing is involved, surface tooling should call into the Rust ledger/core
  (or a formally specified reference implementation) and treat its output as authoritative.

#### Protocol-critical operations

The following operations are authoritative in Rust. Python implementations of the same operations exist as
fallbacks for environments without the native extension, but the Rust output is canonical when present.

| Operation                                   | Authoritative crate                | Governing ADR    |
| ------------------------------------------- | ---------------------------------- | ---------------- |
| Canonical JSON encoding for commitments     | `trackone-ledger`                  | ADR-003          |
| Merkle leaf hashing and root computation    | `trackone-ledger`, `trackone-core` | ADR-003          |
| Canonical `day.bin` / block-header stamping | `trackone-ledger`                  | ADR-003          |
| Canonical CBOR commitment encoding          | `trackone-core` (`cbor.rs`)        | ADR-034          |
| AEAD encrypt/decrypt (XChaCha20-Poly1305)   | `trackone-core`                    | ADR-001          |
| Ed25519 sign/verify                         | `trackone-core`                    | ADR-001, ADR-037 |
| X25519 + HKDF key derivation                | `trackone-core`                    | ADR-001          |

Surface tooling (Python) is authoritative for:

- Pipeline orchestration and I/O (file layout, CLI flags, OTS client invocation).
- Operator-facing output formatting and reporting.
- Test harness structure and fixture management.

### 2. Keep the native module as an implementation detail with a stable name

- The PyO3 extension module name remains **`trackone_core`** (native).
- Python tooling may import it opportunistically:
  - If present: use it for canonicalization / stamping / hashing.
  - If absent: fall back to the Python reference behavior for operator convenience.
  - Environment variable `TRACKONE_NO_EXT=1` forces the fallback path (for debugging/CI).

This keeps Python usable without native compilation while allowing deployments to opt into the Rust-backed path.

### 3. Target `abi3` wheels to reduce the release matrix

For published wheels, TrackOne targets the CPython stable ABI (`abi3`) at the minimum supported Python minor
(per ADR-013). As of this writing, the `abi3` floor is **CPython 3.12**, matching `requires-python` in
`pyproject.toml`.

Practical meaning:

- Build wheels tagged `cp312-abi3` (current minimum).
- A single wheel per platform serves all supported minors (3.12, 3.13, 3.14) without rebuilding.

Constraints:

- The Rust extension must avoid Python C-API usage that is not available under `abi3`.
- If a required feature cannot be supported under `abi3`, we explicitly document the break and either:
  - drop `abi3` for that release line, or
  - gate the feature behind a non-default build.

#### ABI tag evolution

The CPython stable ABI tagging scheme may evolve. PEP 809 proposes a successor (`abi2026`) to the current `abi3`
tag. TrackOne will migrate once PyO3 and maturin support the new scheme. The underlying goal is unchanged:
**one wheel per platform, targeted at the minimum supported CPython minor**.

### 4. Wheel testing has two modes: locked (required) + resolve (gated)

| Mode                          | Trigger                  | What it does                                                                      | Purpose                               |
| ----------------------------- | ------------------------ | --------------------------------------------------------------------------------- | ------------------------------------- |
| **Locked** (`test-wheel`)     | Every PR (required)      | Install deps from committed lock, install wheel without deps, run test suite      | Determinism — "what we meant to ship" |
| **Resolve** (`wheel-resolve`) | Label / dispatch (gated) | `pip install` wheel normally (pip resolves from index), `pip check`, smoke-import | Detect ecosystem drift early          |

The two modes surface different failure classes without conflating them. The gated resolve test is intentionally
opt-in to avoid making every PR subject to index churn.

## Consequences

### Positive

- Clearer trust boundaries: protocol-critical bytes come from one authoritative implementation path, enumerated
  in a concrete table above.
- Lower wheel maintenance cost over time via `abi3` (one build per platform instead of one per minor).
- CI surfaces two different classes of failures (deterministic breakage vs ecosystem drift) without conflating them.
- Aligns with ADR-017's phased rollout: Python fallbacks coexist with the Rust-backed path during migration.

### Negative / Trade-offs

- `abi3` constrains which CPython C-APIs are available; some "nice-to-have" Python integration features may be
  harder to implement.
- Gated resolve tests can miss breakage until explicitly triggered (by design — the trade-off is intentional).
- Keeping a Python fallback path increases short-term maintenance (two implementations during migration). This cost
  decreases as ADR-017 progresses through Phases 2–3 (crypto, then default-on).

## Implementation Notes

1. **Enable `abi3` in PyO3**: add `abi3-py312` to the PyO3 feature list in the workspace `Cargo.toml`:

   ```toml
   [workspace.dependencies]
   pyo3 = { version = "0.28", features = ["extension-module", "abi3-py312"] }
   ```

1. **Verify wheel tags in CI**: after `maturin build`, confirm the wheel filename contains `cp312-abi3` (or the
   expected platform tag). On Linux, `auditwheel show` can validate manylinux compliance.

1. **Fallback testing**: add a CI matrix entry (or tox env) that sets `TRACKONE_NO_EXT=1` and runs the test suite
   to ensure surface tooling degrades gracefully without the native extension.

1. **Protocol-critical boundary enforcement**: Rust-side code reviews should verify that new commitment or hashing
   logic lives in the authoritative crates listed above, not in Python scripts.

## Alternatives Considered

1. **Per-minor wheels only (no `abi3`)**

   - Simpler to implement initially, but increases the build/test/publish matrix and ongoing maintenance cost.
   - Rejected: the additional CI/release burden is not justified given TrackOne's current scope.

1. **Make the Rust extension mandatory**

   - Stronger single-source-of-truth enforcement, but harms operator ergonomics and makes some environments harder
     to support (no Rust toolchain, platform wheel gaps).
   - Rejected: conflicts with ADR-017 Phase 1–2, which explicitly supports Python fallbacks.

1. **Pure-Python only**

   - Minimizes packaging complexity but makes it harder to single-source protocol-critical byte production and
     leaves performance headroom on gateways.
   - Rejected: per ADR-017 and ADR-034, Rust is the authoritative implementation for commitments and crypto.

## Testing & Migration

No migration required; this ADR formalizes existing conventions and names the next implementation steps.

Acceptance criteria for `abi3` readiness:

- [ ] `abi3-py312` feature enabled in `pyo3` workspace dependency.
- [x] A single wheel artifact installs and passes the test suite on CPython 3.12, 3.13, and 3.14.
- [x] The locked wheel test (`test-wheel`) runs the full test suite against the installed wheel on every PR.
- [x] The gated resolve test (`wheel-resolve`) can be triggered to check "pip reality" without requiring lock changes.
- [ ] Wheel filename contains the expected `cp312-abi3` tag (verified in CI).

## External References

- [PEP 384 – Defining a Stable ABI](https://peps.python.org/pep-0384/)
- [PEP 809 – Stable ABI for the Future](https://peps.python.org/pep-0809/) (proposed successor: `abi2026`)
- [PyO3 `abi3` documentation](https://pyo3.rs/v0.28.0/building-and-distribution/multiple-python-versions)
- [maturin documentation](https://github.com/PyO3/maturin)
