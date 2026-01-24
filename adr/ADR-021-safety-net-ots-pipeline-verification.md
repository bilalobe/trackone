# ADR-021: Safety net for OTS pipeline and verification

**Status**: Proposed
**Date**: 2025-11-25

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md): Merkle canonicalization and OTS anchoring
- [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md): OTS CI verification and Bitcoin headers
- [ADR-008](ADR-008-m4-completion-ots-workflow.md): M4 completion OTS workflow
- [ADR-010](ADR-010-test-suite-refactor-structure-naming.md): Test suite refactor, structure, naming
- [ADR-014](ADR-014-stationary-ots-calendar.md): Stationary OTS calendar
- [ADR-018](ADR-018-cryptographic-randomness-and-nonce-policy.md): Cryptographic randomness and nonce policy
- [ADR-020](ADR-020-stationary-ots-calendar-followup.md): Stationary OTS calendar follow-up
- [ADR-022](ADR-022-first-party-stationary-ots-calendar-service.md): First-party stationary OTS calendar service in CI
- [ADR-024](ADR-024-anti-replay-and-ots-backed-ledger.md): Anti-replay and OTS-backed ledger
- [ADR-030](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md): EnvFact schema and duty-cycled day.bin anchoring

## Context

TrackOne’s OTS / calendar / verification pipeline anchors data to Bitcoin and later verifies proofs (`ots_anchor.py`, stationary calendar sidecar, `verify_cli`, CI jobs, and downstream tooling).

We are **not** targeting full IEC 61508 or safety certification. Instead, we want a pragmatic software-only **safety net** that:

- Prioritizes data integrity, auditability, and operational safety.
- Focuses on avoiding corrupted proofs, incorrect day roots, silent data loss, and misleading verification results.
- Leverages existing tests, schemas, ADRs, CI gates, and monitoring rather than introducing a parallel safety bureaucracy.

This ADR sets a common language for “how bad is it if this goes wrong?” and ties key mishaps to specific mitigations.

## Scope

In scope:

- Logical/data correctness of:
  - OTS anchoring (`ots_anchor.py`, gateway integration, Bitcoin headers).
  - Stationary calendar sidecar and public calendar selection.
  - Verification CLI (`verify_cli`) and related APIs.
  - CI jobs that exercise anchoring, upgrading, and verification.
- Auditability:
  - Being able to reconstruct *what happened* with proofs and calendar endpoints.
- Operational safety:
  - Avoiding “dangerous surprises” in automation (CI, batch jobs, migrations).

Out of scope:

- Physical injury hazards, hardware safety, facilities safety.
- Full IEC 61508 or SIL certification; IEC 61508 is only an **inspiration** for having impact levels.

## “SIL-lite” impact levels

We classify failures on a simple three-level scale.

- **Low impact (L)**

  - Inconvenience, noisy logs, transient CI flakes with clear visibility.
  - Examples: retriable network errors to calendars; non-critical telemetry gaps.

- **Medium impact (M)**

  - Localized data or proof issues, but with:
    - Detectable symptoms (tests fail, alerts fire, verification CLI warns), and
    - Feasible remediation (re-anchor, re-ingest, rerun jobs).
  - Examples: a batch of proofs must be regenerated; a CI job blocks a release.

- **High impact (H)**

  - Silent or hard-to-detect integrity failures:
    - Wrong day_root accepted and published.
    - Corrupted proofs treated as valid.
    - System claims “verified” when proofs are wrong or missing.
  - Recovery may be expensive and may erode trust in the pipeline.

Component mapping (current assumptions):

| Component / area                                     | Typical worst impact | Notes                                                |
| ---------------------------------------------------- | -------------------- | ---------------------------------------------------- |
| `verify_cli` and verification APIs                   | H                    | Can mislead users about proof validity.              |
| `ots_anchor.py` and anchoring gateway pipeline       | H                    | Controls inclusion and day_root correctness.         |
| Stationary calendar sidecar + calendar selection     | M → H                | Misrouting to bad calendars can skew proofs.         |
| CI jobs for OTS / calendar / verification (tox envs) | M                    | Mostly gatekeeping, but misconfig can hide H issues. |
| Proof storage / metadata (e.g. `proofs/*.meta.json`) | M → H                | Corruption can invalidate or misclassify proofs.     |
| Telemetry / observability around OTS flows           | L → M                | Loss reduces ability to detect/diagnose issues.      |

## Potential mishaps and mitigations

The following list is not exhaustive but covers the main classes of software-only hazards. For each, we tie mitigations to existing/planned mechanisms.

### 1. Corrupted proofs treated as valid (H)

Examples:

- Truncated or malformed `.ots` files still reported as “OK”.
- Mismatched file content vs. proof (hash mismatch) not detected.
- Upgraded proofs that no longer match original anchors.

Mitigations:

- **Verification strictness:**

  - `verify_cli` and library verification functions must:
    - Recompute hashes from input data and proofs.
    - Fail closed on parse errors, missing steps, or mismatched digests.
  - Tests (current repo paths):
    - `tests/integration/test_verify_cli.py` covers Merkle root recomputation and end-to-end verification glue.
    - `tests/integration/test_ots_integration.py` covers real-OTS stamping/verification when explicitly enabled (`RUN_REAL_OTS=1`).
    - `tests/e2e/test_pipeline_integration.py` exercises the full pipeline and verifies CLI success on produced artifacts.

- **Schema and invariants:**

  - Proof metadata (e.g. `proofs/*.ots.meta.json`) must:
    - Use explicit schemas (forward-only where possible; see `ADR-006-forward-only-schema-and-salt8.md`).
    - Be validated on load (unknown fields tolerated, but missing required fields cause failure).

- **CI gates:**

  - Tox environments (`ots`, `slow`, `verify`) must:
    - Run negative tests for corrupted or tampered proofs.
    - Run at least one end-to-end verify flow per change touching OTS/verification code.
  - GitHub Actions workflow for OTS/verification must:
    - Fail on any test failure or unexpected warning from `verify_cli`.

- **Operational guidance:**

  - `docs/ots-verification.md` documents:
    - That “verified” means **cryptographically** checked end to end.
    - That any parsing or hash mismatch is a hard failure, not downgraded to a warning.

### 2. Wrong day_root accepted or published (H)

Examples:

- Incorrect aggregation of leaves into Merkle trees (ordering, salt misuse).
- Bug in canonicalization causing different producers to compute different roots.
- CI job or manual process publishes a wrong per-day root as authoritative.

Mitigations:

- **Canonicalization and Merkle discipline:**

  - Follow `ADR-003-merkle-canonicalization-and-ots-anchoring.md`:
    - Stable ordering of leaves.
    - Explicit salting rules, integrated with `ADR-006` for salt usage.
  - Tests (current repo paths):
    - `tests/integration/test_verify_cli.py::TestVerifyCli::test_merkle_root_computation_matches_batcher` validates that Merkle roots computed by `verify_cli` match those computed by `merkle_batcher`.
    - `tests/integration/test_replay_merkle_integration.py` covers duplicate handling and deterministic batching behavior feeding `day.bin`.
    - `tests/e2e/test_pipeline_integration.py` covers an end-to-end reproduction path from frame verification through batching.

- **Anchoring and Bitcoin headers checks:**

  - `ADR-007-ots-ci-verification-and-bitcoin-headers.md`:
    - Defines how Bitcoin headers are fetched, compared, and pinned.
  - Tests:
    - OTS verification tests that re-derive expected roots from proofs and headers.
    - Edge-case tests around duplicate leaves, empty batches, and large batches.

- **CI guardrails:**

  - CI jobs that produce or publish day_roots must:
    - Run Merkle repro tests on a sample of recent batches.
    - Compare computed day_roots against expected values for known fixtures.
    - Fail if any mismatch or non-determinism is detected.

- **Auditability:**

  - Store:
    - Input set hashes (per batch) and derived day_roots.
    - Versioned code bundle identifiers (git SHA, ADR references).
  - This allows later reproduction and forensic analysis if a day_root is disputed.

### 3. Stationary calendar or calendar selection misbehaving (M → H)

Examples:

- Stationary calendar sidecar returns stale or inconsistent results.
- Misconfigured `OTS_CALENDARS` causing traffic to untrusted or test calendars in production.
- CI tests accidentally running against real public calendars when they should be stubbed, or vice versa.

Mitigations:

- **Clear role of stationary calendar sidecar:**

  - `ADR-014` and `ADR-020` define:
    - Sidecar is a controlled OTS client/tooling environment, **not** yet a full HTTP calendar.
    - `RUN_REAL_OTS=0` in `ots-cal` tox env to avoid reliance on real calendars.

- **Configuration discipline:**

  - `OTS_CALENDARS`:
    - Default ordering: trusted calendars first, test/staging calendars explicitly marked.
    - Separate configs for CI vs. production (e.g., different environment variables or config files).

- **Tests and markers:**

  - Tox environments:
    - `ots-cal`: smoke tests for tooling with `real_ots` tests skipped.
    - `ots` / `slow`: run `real_ots` tests explicitly against public calendars.
  - Tests:
    - Marks and fixtures (`real_ots`) to ensure:
      - No accidental hitting of public calendars in purely offline CI runs.
      - Explicit opt-in for “real” OTS integration tests.

- **Monitoring and logs:**

  - Calendar selection and endpoints:
    - Log which calendar URL was used for a given operation (without leaking secrets).
    - Provide metrics on failures per calendar endpoint.

- **Operational documentation:**

  - `docs/ots-verification.md` and README sections clarify:
    - How to switch between public and stationary/calendar-sidecar endpoints.
    - How to run CI locally with or without real OTS access.

### 4. CI misconfiguration masks real regressions (M → H)

Examples:

- Important tests (`real_ots`, negative-path verifications) accidentally skipped.
- New components (e.g., Rust core via `pyo3`, see `ADR-017`) added without corresponding tests.
- CI jobs green even though OTS-related tests are not running.

Mitigations:

- **Test suite structure:**

  - `ADR-010-test-suite-refactor-structure-naming.md`:
    - Defines consistent naming and grouping of tests.
  - Ensure:
    - OTS and verification-critical tests live under predictable paths:
      - `tests/integration/test_ots_integration.py`
      - `tests/integration/test_verify_cli.py`
      - `tests/e2e/test_pipeline_integration.py`

- **CI coverage contracts:**

  - For each tox environment (e.g., `py3X`, `ots`, `ots-cal`, `slow`):
    - Document which tests **must** run.
    - Have a small meta-test (or script) asserting that expected markers and files are collected.
  - CI jobs must:
    - Fail if no tests are collected for a critical environment.
    - Fail if key tox envs (`ots`, `ots-cal`, `verify`) are skipped.

- **Change review practices:**

  - Changes to:
    - `tox.ini`, GitHub Actions workflows, or `Makefile` targets that affect tests:
      - Require at least one reviewer familiar with OTS/verification.
      - Should link to this ADR in the PR description when test coverage is reduced.

- **Telemetry:**

  - Simple CI metrics:
    - Number of tests run per job.
    - Presence of `real_ots` tests in scheduled/nightly pipelines.

### 5. Data loss or incomplete history of proofs (M → H)

Examples:

- Proof files deleted or overwritten without trace.
- Metadata (`*.meta.json`) out of sync with `.ots` files.
- Retention policies or cleanups remove data needed for audits or re-verification.

Mitigations:

- **Storage and schema:**

  - Proofs and metadata:
    - Stored in versioned structures (e.g., under `proofs/YYYY-MM-DD/`).
    - Follow forward-only schema rules (see `ADR-006`), avoiding destructive migrations.

- **Invariants and checks:**

  - Periodic CI or scheduled jobs:
    - Enumerate stored proofs and confirm:
      - For each `.ots`, a corresponding metadata record exists and passes schema validation.
      - For each metadata record, associated `.ots` exists and can be verified.
  - Tests:
    - Add tests for round-tripping metadata + proofs (create → store → reload → verify).

- **Backups and retention:**

  - Define minimal retention expectations (e.g., “keep proofs and metadata for N years or according to project policy”).
  - Ensure:
    - Any cleanup scripts have a dry-run mode and require explicit opt-in.
    - Cleanups are tested on synthetic datasets before production use.

- **Audit logs:**

  - Record:
    - When proofs or metadata are created, updated, or deleted.
  - Even if logs are coarse (per-batch), this supports root-cause analysis.

### 6. Unsafe or weak randomness affecting proofs (M → H)

Examples:

- Non-CSPRNG sources used for salts or nonces in Merkle or OTS-related flows.
- Test-only deterministic RNGs accidentally enabled in production.

Mitigations:

- **Randomness policy:**

  - `ADR-018-cryptographic-randomness-and-nonce-policy.md`:
    - Only OS-backed CSPRNGs (`secrets`, `os.urandom`, `OsRng`) for cryptographic randomness.
    - `random`, `numpy.random`, and ad-hoc PRNGs prohibited in production crypto contexts.

- **Tooling and enforcement:**

  - AST-based lint (`scripts/lint/check_prohibited_rngs.py`):
    - Runs in pre-commit and CI.
    - Flags prohibited RNG usage, with explicit suppression markers only for justified cases (e.g., tests).

- **Tests:**

  - Crypto unit tests:
    - Confirm nonce and salt lengths and uniqueness properties where applicable.
  - Negative tests:
    - Ensure that production code paths do not reference disallowed RNG APIs.

### 7. Misleading verification UX / operator error (M → H)

Examples:

- `verify_cli` default output interpreted as “everything is fine” even when there are warnings.
- Non-zero exit codes not wired correctly in automation.
- Operators misunderstanding “upgradeable”, “partial”, or “incomplete” proofs.

Mitigations:

- **CLI behavior:**

  - `verify_cli` must:
    - Use exit codes that reflect success vs. failure vs. partial/incomplete.
    - Print explicit, concise messages for:
      - Valid proofs.
      - Incomplete but upgradeable proofs.
      - Invalid proofs or mismatches.

- **Tests:**

  - CLI tests under `tests/test_verify_cli.py` (or equivalent):
    - Cover exit codes and text output for:
      - Valid proof.
      - Invalid/malformed proof.
      - Missing proof file.
      - Proof missing expected anchors.

- **Documentation:**

  - `docs/ots-verification.md`:
    - Includes examples of:
      - Typical CLI output in success and failure modes.
      - How to interpret partial or “not yet anchored” results.
    - Explicitly instructs automation to rely on exit codes, not just text parsing.

## Success criteria and verification

We consider this ADR “effectively implemented” when:

- **Tests:**

  - All relevant test modules pass in CI, including at least:
    - `tests/e2e/test_pipeline_integration.py`
    - `tests/integration/test_verify_cli.py`
    - `tests/integration/test_replay_merkle_integration.py`
    - `tests/integration/test_ots_integration.py` (skipped unless explicitly enabled via `RUN_REAL_OTS=1`)
  - Negative-path tests for corrupted proofs, misconfigured calendars, and malformed metadata are present and stable.

- **CI jobs:**

  - Tox environments run in CI:
    - `ots`, `ots-cal`, `verify`, and standard `py3X`:
      - Are all green on main.
      - Fail if **no tests** are collected.
  - CI includes:
    - `scripts/lint/check_prohibited_rngs.py` (or equivalent) in at least one required job.
    - Jobs that exercise OTS integration and `real_ots`-tagged tests on a scheduled (e.g., nightly) basis, even if not on every PR.

- **Monitoring and observability:**

  - At least basic metrics and logs exist for:
    - Number of proofs processed, verified, and failed.
    - Calendar endpoints used and error rates.
  - Alerting thresholds for:
    - Sudden spike in verification failures.
    - Persistent errors talking to all configured calendars.

- **Documentation and ADR links:**

  - `docs/ots-verification.md` and relevant README sections:
    - Reference this ADR for safety-net rationale.
    - Describe how CI jobs, tests, and config variables (e.g., `OTS_CALENDARS`, `RUN_REAL_OTS`) interact.

If any of these criteria regress (e.g., CI skips OTS tests, or proof metadata schema checks are removed), the regression should be treated as at least a **medium-impact (M)** safety event and corrected before relying on the pipeline for high-impact use cases.

## Non-goals

- Achieving formal SIL ratings or IEC 61508 certification.
- Introducing a separate “safety” implementation track; we rely on:
  - Strong defaults.
  - Thorough tests and CI.
  - Clear documentation and operator guidance.

The intent is a practical, reviewable safety net that can evolve alongside the rest of the TrackOne architecture.

## See also

- [ADR-003: Merkle canonicalization and OTS anchoring](ADR-003-merkle-canonicalization-and-ots-anchoring.md)
- [ADR-007: OTS CI verification and Bitcoin headers](ADR-007-ots-ci-verification-and-bitcoin-headers.md)
- [ADR-008: M4 completion OTS workflow](ADR-008-m4-completion-ots-workflow.md)
- [ADR-010: Test suite refactor, structure, naming](ADR-010-test-suite-refactor-structure-naming.md)
- [ADR-014: Stationary OTS calendar](ADR-014-stationary-ots-calendar.md)
- [ADR-018: Cryptographic randomness and nonce policy](ADR-018-cryptographic-randomness-and-nonce-policy.md)
- [ADR-020: Stationary OTS calendar follow-up](ADR-020-stationary-ots-calendar-followup.md)
- [ADR-022: First-party stationary OTS calendar service in CI](ADR-022-first-party-stationary-ots-calendar-service.md)
- [ADR-024: Anti-replay and OTS-backed ledger](ADR-024-anti-replay-and-ots-backed-ledger.md)
- [ADR-030: EnvFact schema and duty-cycled day.bin anchoring](ADR-030-envfacts-sensorthings-and-duty-cycled-anchoring.md)
