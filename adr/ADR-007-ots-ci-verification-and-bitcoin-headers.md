# ADR-007: OTS Verification in CI and Bitcoin Headers Policy

**Status**: Accepted
**Date**: 2025-10-20

## Context

- OpenTimestamps (OTS) anchoring is core to our auditability guarantees (ADR-003). Verifying OTS proofs requires access to Bitcoin block headers that contain the relevant attestations.
- Running a fully-synced Bitcoin Core node in CI is impractical (multi‑day sync, >500 GB). Even a fresh headers sync can be slow without caching.
- We need a deterministic, repeatable verification strategy that is feasible for CI and developer laptops while preserving trust properties.

## Decision

Adopt a two-tier verification policy:

1. Headers-only Bitcoin Core for trustless verification

- Run bitcoind in headers-only/pruned mode (no full blocks) with low resource usage.
- Persist the Bitcoin datadir between CI runs to reuse downloaded headers.
- In CI, parse required block heights from .ots files and wait until headers reach the highest required height before running `ots verify`.

2. Graceful fallback when headers are unavailable

- If a CI job cannot reach required headers within a bounded timeout (e.g., 10 minutes), skip OTS verify for those artifacts with a clear, non-failing note.
- Allow offline/manual verification outside CI using a machine with synced headers.

Implementation notes

- Start bitcoind with: `-listen=0 -blocksonly=1 -prune=550 -txindex=0 -dbcache=50`.
- Cache `~/.bitcoin` between runs (CI cache key includes OS and Bitcoin Core version).
- Extract required heights by parsing `ots info <file.ots>` for `BitcoinBlockHeaderAttestation(<height>)`.
- Poll `bitcoin-cli getblockchaininfo` until `headers >= max_required_height` or timeout.

## Consequences

Positive

- Trustless verification preserved using Bitcoin headers; no dependency on third-party explorers for acceptance.
- CI remains fast and stable by caching headers; most runs verify in seconds.
- Clear operational path for air-gapped or resource-limited environments.

Negative / Trade-offs

- First run in a new CI runner incurs a one-time header sync (10–20 minutes depending on network).
- Requires running bitcoind in CI containers/VMs.
- Fallback path temporarily skips verification when headers lag; auditors must verify later on a synced machine.

## Alternatives Considered

- Full node in CI: Too heavy (storage/time).
- Third-party block explorer APIs only: Quicker, but weakens trust model (centralized dependency); rejected for acceptance criteria.
- Electrum/SPV clients: Lighter than full node, but adds extra dependencies and complexity; deprioritized.

## Testing & Migration

- Add a CI helper script to:
  1. Start bitcoind (headers-only)
  1. Collect heights from `ots info` output
  1. Wait for headers to catch up (with timeout)
  1. Run `ots verify` and record results
- Developers can verify locally using the same script; document expectations and timeouts.

## Acceptance Criteria

- `ots verify` passes in CI when cached headers cover the attested heights.
- On cache misses or network issues, CI logs a “verification deferred” note and does not fail the build.
- Documentation updated (report + README) describing headers-only mode and caching, and referencing this ADR.
