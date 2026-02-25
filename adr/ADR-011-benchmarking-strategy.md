# ADR-011: Benchmarking Strategy for TrackOne

**Status**: Accepted
**Date**: 2025-11-01
**Updated**: 2026-02-25

## Context

- We've stabilized crypto, framing, and gateway pipeline code paths (ADR-001, ADR-002, ADR-003, ADR-005) and significantly refactored tests (ADR-010).
- The repository now uses a single canonical implementation for the pod simulator at `scripts/pod_sim/pod_sim.py`; legacy top-level shims/fallbacks were removed to avoid ambiguity during test/bench runs.
- Formatting and linting are enforced in CI; formatting regressions (Black) can cause `make lint` failures if not applied locally.
- Performance and allocation profiles matter for scale (device count, frame rates, day-chain throughput) and to prevent regressions during future refactors.
- pytest and pytest-benchmark are available; there's a `tests/bench/` folder intended for micro/mid-level benchmarks.

## Progress update

- Repository changes completed:
  - All tests and fixtures were updated to import the canonical `scripts/pod_sim/pod_sim.py` directly (no preferred/legacy fallbacks).
  - The top-level shim that previously shadowed the canonical implementation was removed/replaced to avoid accidental imports.
  - The canonical `scripts/pod_sim/pod_sim.py` has been formatted with Black and `make lint` was exercised to ensure linter rules are respected.
- Practical implications for benchmarking:
  - Benchmarks must import and exercise the canonical modules (not legacy shims) to ensure measured code matches production paths.
  - Bench harnesses should be robust to lint/format gating: run `black` before saving or committing benchmark scaffolding to avoid CI lint failures.

## Decision

Adopt a lightweight, code-as-benchmark approach built on pytest-benchmark, with a small curated suite that runs locally by default and optionally in CI with soft thresholds.

Scope (initial):

- Crypto microbenchmarks (scripts/gateway/crypto_utils.py)
  - xchacha20poly1305_ietf_encrypt/decrypt: typical payload sizes (64B, 512B, 4KB)
  - hkdf_sha256: varied lengths (32, 64 bytes) and info contexts
  - x25519_shared_secret and ed25519_sign/verify
- Gateway unit-level benchmarks
  - canonical_json and merkle_root_from_leaves (varied leaf counts)
  - frame_verifier.aead_decrypt + parse_frame (representative frame sizes); ensure frames are produced via canonical `pod_sim.emit_framed` in tests/fixtures
- End-to-end sample
  - verify_cli.merkle_root + verify_ots (placeholder path; real OTS gated/optional)

Out-of-scope (initial):

- Full-scale soak/load testing (handled by a separate tool/runner in the future)
- OS-level profiling automation; we’ll document manual use of perf/py-spy.

## Rationale

- pytest-benchmark integrates with our existing pytest layout, supports regression comparison (saved JSON), and requires minimal harness code.
- Co-locating minimal fixtures with existing test fixtures keeps maintenance low and leverages curated data.
- Keeping CI gating soft at first reduces churn from noisy environments while still giving signal.

## Plan & Conventions

Directory layout:

- `tests/bench/` contains benchmark modules (names start with `bench_*.py`).
- Reuse fixtures from submodule confts where possible; avoid duplicating generators.

Data and artifacts:

- Write benchmark runs to `out/benchmarks/` (JSON files created by pytest-benchmark), which stays git-ignored.
- Optionally keep a golden reference JSON for local comparisons in `toolset/unified/benchmarks/` (checked in) when a metric is stable.

Running (local examples):

- Quick run: `pytest tests/bench -q --benchmark-only`
- Save baseline:
  - `pytest tests/bench --benchmark-only --benchmark-save=baseline`
- Compare to baseline:
  - `pytest tests/bench --benchmark-only --benchmark-compare=baseline`

Stability guidelines:

- Run on AC power, low background load.
- Prefer release builds and pinned Python/dep versions.
- Use `--benchmark-warmup` and multiple rounds (pytest-benchmark defaults are fine; adjust per bench if needed).

Best-practices for benches in this repo:

- Import canonical modules only (e.g., `from scripts.pod_sim import emit_framed`). Do not rely on legacy top-level shims.
- Keep benchmarks small and deterministic: fixed random seeds where applicable or use deterministic fixtures.
- Format and lint benchmark files before committing; CI will run linters.

## CI Strategy

- Add an optional job that runs `pytest tests/bench --benchmark-only --benchmark-save=ci` and uploads JSON as artifact.
- For selected stable microbenchmarks, set soft regression thresholds (for example, `--benchmark-min-rounds=10`) and treat regressions as warnings in early phases. Only fail CI on severe regressions (configurable threshold) or repeated trends.
- Skip OTS networked operations (keep them behind env flag) to avoid non-determinism.
- Run `black` as part of pre-commit or CI lint stage; failing formatting should be fixed locally.

## Alternatives Considered

- asv (Airspeed Velocity): powerful for historical tracking, but heavier setup and separate runner; overkill right now.
- pyperf: robust for CPython benchmarking and variance control; good later for hotspot deep-dives, but pytest-benchmark matches our workflow now.
- Ad-hoc timeit scripts: easy but hard to standardize and compare over time.

## Consequences

Positive:

- Early detection of performance regressions in crypto and pipeline primitives.
- Shared conventions and location reduce benchmark bit-rot.
- Easy local usage for developers; optional CI signal.

Negative / Risks:

- Benchmark noise in CI; mitigated via soft thresholds and artifact-only runs initially.
- Maintenance overhead if the suite grows without ownership; mitigate by curating a small set and reusing fixtures.

## Implementation Notes (Initial Bench Stubs)

- Create `tests/bench/bench_crypto.py` covering hkdf, xchacha encrypt/decrypt at fixed sizes, x25519, ed25519.
- Create `tests/bench/bench_gateway.py` covering canonical_json, merkle_root_from_leaves, parse_frame+aead_decrypt on a small synthetic frame.
- Use existing fixtures from `tests/unit/crypto` and `tests/unit/gateway` conftests; import canonical modules directly.
- Ensure outputs are consumed (e.g., assert on lengths) to prevent dead-code elimination.

## Testing & Migration

- Developers validate locally with `--benchmark-only` and save a baseline when stable.
- Add a Makefile target `bench` to run the suite and place results under `out/benchmarks/` (recommended next step).
- Iterate: start with microbenchmarks for crypto primitives; expand only where there’s a clear need (e.g., regression reports or feature work).
