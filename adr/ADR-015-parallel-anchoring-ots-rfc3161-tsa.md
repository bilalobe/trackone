# ADR-015: Parallel Anchoring with OpenTimestamps and RFC 3161 TSA

**Status**: Accepted
**Date**: 2025-11-06
**Updated**: 2026-02-25

## Related ADRs

- [ADR-003](ADR-003-merkle-canonicalization-and-ots-anchoring.md) (Canonicalization & OTS anchoring)
- [ADR-007](ADR-007-ots-ci-verification-and-bitcoin-headers.md) (OTS CI verification)
- [ADR-014](ADR-014-stationary-ots-calendar.md) (Stationary OTS calendar)
- [ADR-008](ADR-008-m4-completion-ots-workflow.md) (M#4 OTS workflow and metadata)
- [ADR-017](ADR-017-rust-core-and-pyo3-integration.md) (Rust CLI verification — optional future verifier)
- [ADR-041](ADR-041-verification-disclosure-bundles-and-privacy-tiers.md) (Disclosure classes for verifier claims)

## Implementation Summary

- **Pipeline**: `run_pipeline_demo.py` supports `--tsa-url`, `--peer-config` flags to enable parallel anchoring
- **Verification**: `verify_cli.py` supports `--verify-tsa`, `--verify-peers` with strict/warn modes
- **Artifacts**: TSA (`*.tsq`, `*.tsr`, `*.tsr.json`) and peer (`*.peers.json`) stored under `out/site_demo/day/`
- **Manifest**: Pipeline manifest tracks TSA and peer artifacts for automated verification discovery
- **Tests**: Integration tests cover warn/strict modes for TSA and peer verification
- **Demo config**: `toolset/demo_peer_config.json` provides sample peer keys for local testing
- **Exit codes**: 5=TSA failed (strict), 6=peer failed (strict)

## Context

TrackOne currently anchors daily Merkle roots using OpenTimestamps (OTS) per ADR-003 and verifies them in CI per ADR-007. OTS gives decentralized, trust-minimized timestamp proofs via Bitcoin calendars. Some stakeholders (heritage/public institutions) require compatibility with formal / accredited timestamp authorities (RFC 3161 / ETSI EN 319 421) for policy and audit traceability. Additionally, social / peer trust (multi-party co-signing) strengthens assurances.

Challenges:

- OTS proofs depend on Bitcoin inclusion latency (minutes to hours) and block headers availability.
- RFC 3161 TSA responses provide immediate signed time but require trusting the TSA's private key and audit process.
- We need a storage model and verification workflow that allows using both in parallel without duplicating hashing work.

## Decision

Adopt parallel daily anchoring: for each day `D` and site `S` we produce a single canonical `day_root` and generate both an OTS proof and an RFC 3161 TSA response over the same 32-byte digest. We store both artifacts side-by-side and treat successful verification of either anchor as sufficient for "timestamp obtained" while preferring *dual verification* for stronger assurance.

### Scope

- Hash input: the existing canonical day record (hash-sorted Merkle root over that day’s fact/block set) as defined in ADR-003; no change to hashing algorithm (SHA-256) in this ADR.
- Artifacts written under `out/<site>/day/`:
  - `YYYY-MM-DD.bin` — canonical serialized day record (unchanged)
  - `YYYY-MM-DD.bin.ots` — OpenTimestamps proof (unchanged path semantics)
  - `YYYY-MM-DD.tsq` — RFC 3161 timestamp query (DER)
  - `YYYY-MM-DD.tsr` — RFC 3161 timestamp response (DER)
  - `YYYY-MM-DD.tsr.json` — parsed metadata (policy OID, genTime, TSA name, nonce, imprint hash)
  - `tsa_ca.pem` / optional `tsa_chain.pem` — CA materials for verification (if not global)
  - `YYYY-MM-DD.peers.json` (optional) — array of peer co-signatures `{peer_id, sig_hex, pubkey_hex}`

### Workflow

1. Compute `day_root` after final block ingestion for day D.
1. Submit root to OTS calendar (existing code) yielding `.bin.ots`.
1. Build RFC 3161 query (`openssl ts -query`) over `YYYY-MM-DD.bin` (SHA-256 imprint); send to configured TSA URL; store `.tsr`.
1. Parse `.tsr` to JSON metadata (`openssl ts -reply -in ... -text` or ASN.1 decode lib) and persist.
1. (Optional) Distribute `(site_id, date, day_root)` to peers; collect detached Ed25519 signatures; append to `YYYY-MM-DD.peers.json`.
1. Mark anchoring status in ledger index: `ots_verified`, `tsa_verified`, `peer_signatures_count`.

### Verification Policy

- CI: Attempt OTS verify; attempt TSA verify; record results. Failure of one does **not** fail the build if the other succeeds (configurable threshold). Dual failure fails.
- Dashboard: Show three badges (OTS, TSA, Peer) with states: `pending`, `verified`, `failed`, `skipped`.
- CLI (`verify_cli.py`) gains flags:
  - `--verify-ots`, `--verify-tsa`, `--verify-peers`, `--require-all`.

### Resilience Claims and Limits (Quantified Scope)

This ADR makes bounded resilience claims, not absolute ones:

- **Calendar outage resilience**: if one OTS calendar is unavailable, anchoring can
  proceed via other configured calendars.
- **Trust diversification**: OTS + TSA + peer signatures reduce single-anchor dependency.
- **Latency diversification**: TSA may provide near-immediate attestations while OTS
  may require delayed proof upgrades.

Not claimed:

- immunity to coordinated compromise of all selected trust roots;
- guaranteed low latency anchoring under severe network partition;
- semantic correctness of telemetry content (only timing/integrity attestation).

### Adversary Mapping (AT-015)

- **A1: Single calendar outage/misbehavior**
  Mitigated by multi-calendar OTS submission and optional TSA/peer channels.
- **A2: TSA outage or revocation-chain failure**
  Mitigated by OTS path continuity and non-strict verification mode where policy permits.
- **A3: Peer quorum unavailable**
  Limits short-term provenance only; does not invalidate OTS/TSA evidence.
- **A4: Multi-root coordinated compromise**
  Not fully mitigated; requires governance controls (key management, independent operators, auditing cadence).

### Configuration

- Add `anchoring.toml` (or YAML) in project root:

```
[ots]
enabled = true
calendar_urls = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]

[tsa]
enabled = true
url = "https://tsa.example.org/timestamp"
ca_bundle = "out/site_demo/day/tsa_ca.pem"
policy_oid = "0.4.0.2023.1"  # example OID or blank
request_certs = true

[peers]
enabled = true
min_signatures = 2
peer_pubkeys_file = "config/peer_pubkeys.json"
context = "trackone:day_root:v1"
```

## Consequences

### Positive

- Diversified trust: decentralized (OTS) + centralized audited (TSA) + social (peer signatures).
- Faster timestamp availability (immediate RFC 3161) while retaining long-term Bitcoin anchor.
- Policy compliance for institutions needing RFC 3161 evidence packages.
- Backward compatible: existing OTS-only flows remain valid; addition is additive.

### Negative / Trade-offs

- Additional complexity in artifact management and CI checks.
- Need to maintain TSA trust roots and monitor TSA certificate expiration.
- Slight increase in daily runtime and storage (RFC 3161 artifacts are small but non-zero).
- Peer signature workflow introduces operational coordination.
- Parallel channels can create policy ambiguity unless strict/warn behavior is explicitly configured per environment.

### Operational Impact

- New secrets/config for TSA endpoint if authentication required.
- Rotation procedures for TSA CA bundle and peer keys.
- Monitoring tasks: alert if TSA verification starts failing or if OTS proofs lag excessively.

## Alternatives Considered

1. TSA-only anchoring: rejected (loses decentralized assurance; single trust root).
1. OTS-only (status quo): insufficient for stakeholders requiring formal timestamping compliance.
1. Anchoring on public L2 (Polygon) daily instead of TSA: considered; may complement future ADR (cost/gas overhead). Not mutually exclusive—can layer later.
1. Just peer co-signing without TSA: weaker for formal audits lacking standardized timestamp structure.

## Testing & Migration

### Testing

- Unit tests: parse `.tsr` and compare imprint hash to SHA-256 of `YYYY-MM-DD.bin`.
- Property test: invalid imprint (mutated file) causes verification failure.
- Integration test: mock TSA (local Flask) returning canned `.tsr`; ensure parallel success path.
- CI: mark build `yellow` if one verifier passes and the other is pending; `red` if both fail.

### Migration Steps (Post Acceptance)

1. Implement RFC 3161 stamping utility (`tsa_stamp_day_blob`) in gateway code.
1. Extend anchoring pipeline to call TSA logic after OTS.
1. Add verification functions and integrate into `verify_cli.py`.
1. Add configuration file and documentation updates (`README`, operator guide).
1. Backfill TSA artifacts for a limited recent window (optional); mark older days `ots_only`.

### Rollback

- Disable `[tsa].enabled` or `[peers].enabled` flags; pipeline reverts to OTS-only without code removal.

## Future Extensions

- Add L2 (Polygon/Arbitrum) anchor ADR for triple anchoring (cost vs resilience).
- Store TSA response in transparency log (e.g., append `.tsr` hash to Sigstore Rekor) for public audit.
- Threshold signature scheme (e.g., FROST Ed25519) replacing individual peer signatures.

## External References

- RFC 3161: Time-Stamp Protocol (TSP)
- ETSI EN 319 421/422 (Policy & security requirements for TSPs)
