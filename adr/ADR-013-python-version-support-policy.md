# ADR-013: Python Version Support Policy (Last Three Minors)

**Status**: Proposed
**Date**: 2025-11-02

## Context

The Python ecosystem advances quickly and keeping CI green across many minor versions increases maintenance burden. We want a predictable policy that balances coverage, effort, and the ability to use newer language features.

## Decision

TrackOne will support and continuously test against the last three CPython minor versions. When a new CPython minor is released, we will:

- Add the new minor to CI and tox,
- Drop the oldest previously supported minor from the default test matrix, while keeping a dedicated tox env available for explicit runs when needed,
- Keep code and tooling compatible with this rolling three-minor window.

Practical application:

- The CI matrix must always include the three most recently released CPython minor versions. When a new minor is officially released, add it to CI and remove the oldest from the default matrix.
- Maintainers may keep a dedicated tox env for older minors (for example `py311`) for one-off debugging, but these envs are not required to run by default on every PR.
- Document the current supported minors and the rolling-window policy in `README.md` and `CONTRIBUTING.md` so contributors understand how support evolves.

## Consequences

### Positive

- Predictable, rolling window of support.
- Faster CI and lower maintenance by avoiding long tail of minor versions.
- Encourages timely adoption of newer Python features and performance improvements.

### Negative

- Users pinned to older minors may need to test and report issues on their own or upgrade.
- Occasional breakage if upstream dependencies drop older minors shortly after our window changes.

## Alternatives Considered

- Support only the latest minor: too aggressive for most users.
- Support many minors (e.g., last five): higher CI cost for limited value.
- Date-based support windows: adds complexity without clear benefits for this project’s scope.

## Testing & Migration

- CI matrix reflects the last three released minors.
- Lint job runs on the newest minor in the matrix.
- Tox envlist mirrors CI; explicit older envs remain available for one-off checks (e.g., `tox -e py311`) but are not required on every PR.
- Document the policy in README and CONTRIBUTING to set expectations.
