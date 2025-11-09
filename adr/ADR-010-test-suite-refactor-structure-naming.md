# ADR 010: Test suite refactor (structure and naming)

- Status: Proposed
- Date: 2025-10-28
- Owners: QA/Platform

## Context

The test suite had several monolithic or ambiguously named files (e.g., suffixes like `_boost` and `_edge_cases`) that hindered readability, local iteration speed, and targeted test runs. Fixtures were concentrated in top-level files like `'tests/conftest.py'` and `'tests/fixtures/pipeline_fixtures.py'`, increasing global coupling.

Recent work:

- Split the monolithic `'tests/unit/gateway/test_unit_coverage_boost.py'` into focused modules.
- Renamed gateway test files to remove the `_boost` suffix.

## Decision

Adopt a consistent structure and naming for tests and fixtures, and decompose oversized files.

- Structure

  - Keep tests under `'tests/{unit,integration,e2e}'`.
  - Prefer scoped `conftest.py` in each subtree over a single global one.
  - Move reusable helpers to `'tests/fixtures/'` modules imported by tests or scoped `conftest.py`.

- Naming conventions

  - Test files: `test_<topic>.py` (no `_boost`, no `_edge_cases`).
  - Use explicit purpose suffixes only when needed:
    - `..._error_paths.py`, `..._negative.py`, `..._vectors.py`, `..._integration.py`.
  - Avoid ambiguous catch‑all names like `*_edge_cases.py`.

- Size targets (guidelines, not hard limits)

  - Unit: ≤ 150 LOC per file.
  - Integration/E2E: ≤ 200 LOC per file.

- Migration rules

  - Remove `_edge_cases` suffix by renaming `'test_*_edge_cases.py'` → `'test_*.py'` when no conflict exists.
  - Use `git mv` for all renames to preserve history.
  - After each change set: run `'pytest tests/unit/gateway -q'` and then `'pytest -q'`.

- Decomposition targets

  - Split `'tests/integration/test_gateway_pipeline.py'` by scenario/stage.
  - De-scope `'tests/conftest.py'` into `'unit/'`, `'integration/'`, `'e2e/'` specific `conftest.py` or move helpers into `'tests/fixtures/'`.
  - Split `'tests/fixtures/pipeline_fixtures.py'` by domain to reduce import fan‑out.

## Scope

- Rename files to drop `_edge_cases` and maintain explicit, purposeful names for negative/error paths and vectors.
- Split oversized test and fixture modules as listed above.
- No semantic changes to tests; only structure, naming, and import locations.

## Alternatives considered

- Keep existing names and rely on documentation: rejected due to ongoing friction and inconsistent discoverability.
- Collapse tests into fewer modules: rejected, harms focus and parallelization.

## Consequences

- Pros: clearer test intent, faster targeted runs, reduced global fixture coupling, easier reviews.
- Cons: short‑term churn in diffs; potential need to update any tooling that hardcodes paths.

## Implementation plan

1. Rename edge case files

- For each `'tests/unit/gateway/*_edge_cases.py'`: rename to drop `_edge_cases` if target does not exist.
- Repeat similarly for other subtrees if present.

2. Split oversized files

- `'tests/integration/test_gateway_pipeline.py'`: split by scenario/stage; extract shared helpers into `'tests/integration/fixtures/'`.
- `'tests/conftest.py'`: move fixtures closer to usage; keep only truly global items at the root if necessary.
- `'tests/fixtures/pipeline_fixtures.py'`: split per domain and import only where needed.

3. Validation

- Run subset and full suite: `'pytest tests/unit/gateway -q'`, then `'pytest -q'`.
- Ensure CI passes and test discovery remains stable.

## Tooling/CI

- No changes expected unless CI references explicit file paths. If so, update those references to new paths.
- Keep pytest config unchanged unless it filters by old names.

## Risks and mitigations

- Risk: Name conflicts on rename.
  - Mitigate: check targets exist before `git mv`; adjust names to more specific variants if needed.
- Risk: Hidden imports of test modules by name.
  - Mitigate: repo‑wide search for old filenames and update.

## Rollback plan

- Revert the renames and splits via `git revert` of the refactor commits.
- Restore previous `conftest.py` layout if scoped fixtures cause breakage.

## References

- Current structure under `'tests/'`.
- Prior changes removing `_boost` suffix in gateway tests.
- ADR-011: Benchmarking Strategy (benchmarks rely on canonicalized, isolated test fixtures and stable module imports)
- ADR-016: Changelog automation (git-cliff) — consistent commit/test discipline is recommended to produce reliable changelogs
