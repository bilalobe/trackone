# ADR-017: Rust Core and PyO3 Integration Strategy

**Status**: Accepted
**Date**: 2025-11-06
**Milestone Target**: M#6 (post 0.1.0)

## Context

TrackOne currently ships a Python-first gateway with crypto and Merkle logic implemented in Python (libsodium via PyNaCl). For ultra‑low‑power and long‑term maintainability, we want a high‑performance, memory‑safe core that can serve both Python and future embedded/edge targets. Rust offers:

- Safety (no GC, no data races) and predictable performance.
- A path to `no_std` for microcontrollers (future) and `std` for gateways.
- Easy Python bindings via PyO3 and mature packaging via `maturin`.

Constraints:

- Keep Python CLI/API stable for operators; no behavior regressions.
- Determinism: exact parity with existing vectors (AEAD, Ed25519, Merkle).
- Portable wheels (manylinux/musllinux) to avoid local Rust toolchains for users.

## Decision

Adopt a phased migration to a Rust core crate with PyO3 bindings, wired through a Cargo workspace and built with `maturin` as the Python packaging backend. The Rust core is now present in the repo as a workspace with:

- `trackone-core` (Rust library crate)
- `trackone-gateway` (Rust `cdylib` crate exposed to Python via PyO3/maturin)
- `trackone-pod-fw` (Rust firmware crate, currently a stub depending on `trackone-core`)

Python remains the orchestrator (I/O, OTS/TSA, CLI), and the Rust crates are used to progressively take over performance-sensitive paths.

### Scope (initial)

- Crate: `trackone-core` (Rust), published only as Python wheels for now.
- Bindings: PyO3 with `abi3` (cp311+), built with `maturin`.
- Modules (order of rollout):
  1. Canonical JSON (RFC 8785 / JCS) → bytes
  1. Leaf hash (SHA‑256; optional Blake3) and hash‑sorted Merkle root
  1. AEAD XChaCha20‑Poly1305 (deterministic test vectors only; runtime always randomized nonces as spec)
  1. Ed25519 sign/verify; X25519 + HKDF
- Python keeps fallbacks: if Rust extension not present, use pure‑Python/PyNaCl reference.

### API Contract

- No change to Python entry points (`canonical_json`, `merkle_root`, `aead_*`, `ed25519_*`).
- Exact output parity with existing tests/vectors; additional negative tests for misuse.
- Environment flag `TRACKONE_NO_EXT=1` forces fallback (for debugging/CI).

### Packaging & CI

- Build manylinux and musllinux wheels via `maturin build` in CI; upload artifacts to releases.
- Test matrix runs pytest twice: with extension enabled and disabled; both must pass.
- Performance CI (ref ADR‑011) captures baseline benchmarks and publishes trend.

## Consequences

### Positive

- Significant speed/energy gains on gateways; consistent deterministic outputs.
- Safer crypto plumbing; easier to reuse core in non‑Python contexts later.
- Paves way for a `no_std` subset for pods if ever needed.

### Negative / Risks

- Packaging complexity (wheels, manylinux) and larger CI time.
- Crypto implementation choices require careful review (constant‑time ops, key zeroization).
- Temporary duplication: Python reference + Rust core during migration.

## Alternatives Considered

1. C FFI to libsodium directly: fast but harder safety story and ergonomics; platform friction.
1. Cython/Numba acceleration: limited reach for crypto primitives; still Python‑bound.
1. Stay Python‑only: simpler, but leaves performance headroom on constrained gateways.

## Rollout Plan

- Phase 0 (land workspace, latent core): Land the Rust workspace (`trackone-core`, `trackone-gateway`, `trackone-pod-fw`) and basic PyO3 integration; build wheels with `maturin` in CI, but keep Python behavior unchanged.
- Phase 1 (enable hashing/Merkle): Default to Rust for canonicalization+Merkle when the extension is present, keeping Python fallbacks.
- Phase 2 (crypto): Gate AEAD/Ed25519 behind feature flags; enable after vectors and misuse tests stabilize.
- Phase 3 (default on): Use the Rust path by default; keep env flag to disable.
- Phase 4 (optional): Publish a small Rust CLI verifier for auditors (no Python runtime).

## Implementation Notes

- Canonicalization: use `serde_jcs` (JCS). Document precise numeric/UTF‑8 handling; reject NaN/Inf.
- Hashing/Merkle: hash‑sorted leaves; pair hash = H(left || right); duplicate last on odd levels, per ADR‑003.
- AEAD: prefer RustCrypto `xchacha20poly1305` crate; test against our PyNaCl vectors.
- Signatures: `ed25519-dalek` v2; `x25519-dalek`; `hkdf` crate. Validate vectors and negative tests.
- Security: zeroize secrets, avoid branching on secrets, fuzz with `proptest` and AFL/LibFuzzer harnesses.

## Testing & Verification

- Must‑pass suite: existing pytest vectors (happy path + tamper + AAD + edge cases).
- Cross‑lang KATs: generate/reference test vectors for all primitives; verify both directions (Py↔Rust).
- Property tests: canonicalization idempotence; Merkle inclusion proof round‑trip; replay invariants unchanged.

## Operations & Migration

- No user‑visible change to CLI; packaged wheels avoid requiring Rust toolchain for operators.
- Fallback logic ensures identical behavior on platforms without prebuilt wheels.
- Document troubleshooting: env flag, `pip debug --verbose`, wheel platform tags.

## Future Work

- `no_std` core feature for potential pod firmware experiments; WASM bindings for web verifiers.
- Replace select Python modules with Rust progressively (e.g., `verify_cli` fast path) once stable.
- Integrate with ADR‑015 (OTS/TSA) by verifying anchors in Rust CLI for offline audits.

## Acceptance Criteria

- All existing tests pass with and without the extension; coverage maintained.
- Benchmarks show ≥2× speedup for canonicalization+Merkle on gateway class hardware.
- Wheels produced for Linux x86_64 (manylinux, musllinux) in release CI; install tested in a clean venv.

## References

- ADR‑011: Benchmarking Strategy
- ADR‑003: Canonicalization/Merkle Policy
- ADR‑015: Parallel Anchoring with OTS/TSA (integration point for anchor verification)
- ADR‑008: M#4 OTS workflow and metadata (production OTS handling)
- PyO3 (https://pyo3.rs), maturin (https://github.com/PyO3/maturin)
- RustCrypto crates (xchacha20poly1305, ed25519-dalek, hkdf, sha2)
