# ADR-035: Workspace Versioning and Release Visibility (Umbrella vs Per-Crate)

**Status**: Accepted
**Date**: 2026-01-22

## Context

TrackOne is a multi-crate Rust workspace (and a mixed Rust/Python repo). We are already producing multiple artifacts:

- Rust crates (`trackone-core`, `trackone-gateway`, `trackone-pod-fw`, `trackone-constants`, `trackone-bench`).
- A Python-facing artifact built via `maturin` for `trackone-gateway`.
- A container image (`ots-calendar`) used in CI and local Kubernetes.

This creates a practical problem: how to communicate “what shipped” in a way that is:

- **Visible on GitHub Releases** (stakeholders mostly read releases, not ADRs).
- **Internally consistent** (TrackOne’s layered crate model; core evolves faster than gateway/pod stubs).
- **Operationally safe** (avoid implying maturity for crates that are still scaffolding).

We also maintain a top-level `CHANGELOG.md` (Keep a Changelog style).

## Decision

### 1) Use a single workspace (umbrella) version for tags and GitHub Releases

- The repository is tagged and released as an **umbrella version**: e.g. `v0.1.0-alpha.2`.
- All publishable crates in this repo use `version.workspace = true` and therefore share the same version.

Rationale:

- GitHub Releases remain a single canonical “what shipped” surface.
- Avoids release visibility gaps where only one crate bumps but the repo has no release tag.
- Matches TrackOne’s system-level claims: the unit we ship is the **pipeline** (pod → gateway → ledger → OTS).

### 2) Keep the master changelog, and add crate-local changelogs only when a crate becomes independently consumable

- `CHANGELOG.md` remains the primary release note for tags.
- We may add `crates/<crate>/CHANGELOG.md` later **only when**:
  - That crate is published to crates.io or becomes a stable dependency for external users.
  - The crate’s change surface is large enough that it needs its own curated history.

Until then, crate highlights appear in the master changelog under a single umbrella release section.

### 3) In the master changelog, include per-crate “highlights” without overstating maturity

For pre-1.0 alphas:

- Include explicit per-crate bullet lines of the form:
  - “Bumped `trackone-core` to X: <why>”
  - “Bumped `trackone-gateway` to X: <why> (still scaffolding / experimental)”
  - “Bumped `trackone-pod-fw` to X: <why> (skeleton / API shaping only)”

This keeps consistency (one version) while being honest about which parts are production-ready.

## Consequences

### Positive

- One version to reason about for operators and thesis/report citations.
- Release notes are discoverable even if only one crate changes.
- Reduces confusion around compatibility: `trackone-core` schema changes can be tied to a repo tag.

### Negative / Trade-offs

- Some crates will be “bumped” even if changes are minimal.
- Encourages an umbrella cadence; can feel heavier than per-crate releases.

## Alternatives Considered

1. **Per-crate independent versions**

   - Pro: minimal bumps, more granular.
   - Con: GitHub Releases lose visibility; operators must chase multiple version lines; higher cognitive load.

1. **Keep umbrella tags but only bump the changed crate versions**

   - Con: breaks `version.workspace` uniformity and re-introduces drift.

1. **Only do a release when *all* crates are “worthy”**

   - Con: blocks shipping real progress (especially `trackone-core` schema/work) behind less mature crates.

## Implementation Notes

- Use `version.workspace = true` across crates.
- Tag releases at the repo level (e.g., `v0.1.0-alpha.2`).
- Maintain honesty in `CHANGELOG.md` about maturity of gateway/pod layers.
- ADR-016 records and rejects `git-cliff` automation; TrackOne stays manual for now.

## References

- Keep a Changelog (https://keepachangelog.com)
- Semantic Versioning (https://semver.org)
- ADR-016: Changelog automation proposal (Rejected)
- ADR-006: Forward-only schema policy
