# ADR-013: Python Version Support Policy (Last Three Minors)

Status: Proposed
Date: 2025-11-02

## Context

The Python ecosystem advances quickly and keeping CI green across many minor versions increases maintenance burden. We want a predictable policy that balances coverage, effort, and the ability to use newer language features.

## Decision

TrackOne will support and continuously test against the last three CPython minor versions. When a new CPython minor is released, we:

- Add that new minor to CI and tox (e.g., 3.14),
- Drop the oldest previously supported minor from the default test matrix (e.g., 3.11), while keeping a dedicated tox env available for explicit runs when needed,
- Keep code and tooling compatible with this three-minor window.

For this cycle:

- Add Python 3.14 to CI/tox.
- Mark Python 3.11 as unsustained (removed from default envlist/matrix but still runnable via `tox -e py311`).

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

- CI matrix includes the last three minors (currently 3.12, 3.13, 3.14).
- Lint job runs on the newest minor.
- Tox envlist mirrors CI; `py311` remains as an explicit env for one-off checks (`tox -e py311`).
- Document the policy in README and CONTRIBUTING to set expectations.
