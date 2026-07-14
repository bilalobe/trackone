# Verifiable Telemetry Ledger draft-08 conformance

TrackOne implements the additive `verifiable-telemetry-canonical-cbor-v2`
profile from `draft-elkhatabi-verifiable-telemetry-ledgers-08`. Version 1
artifacts and identifiers remain immutable and are not interpreted as v2.

## Conformance boundary

The conformance boundary consists of:

- `trackone-ledger::v2`, which validates exact canonical-record bytes,
  constructs and decodes deterministic segment CBOR, calculates domain-
  separated recursive-split Merkle trees, validates batches, and derives
  successor linkage from exact predecessor bytes;
- `trackone-gateway::v2_producer`, which serializes elapsed-time boundaries
  and admission, snapshots policy, applies close-reason precedence, persists
  exact bytes before acknowledgement, and handles emit, suppress, restart,
  recovery, and contiguous segment allocation;
- `trackone-gateway::v2_postgres`, which provides serializable atomic
  transitions and per-ledger advisory single-writer fencing over PostgreSQL;
- `trackone-evidence verify-v2`, which performs disclosure-aware Class A, B,
  and C validation, race-resistant Linux `openat2` artifact access, segment
  and predecessor validation, exact-byte recomputation, and OpenSSL-backed
  RFC 3161 signature, trust-path, imprint, hash-algorithm, and policy checks;
- the public JSON Schema, CDDL, positive vectors, negative vectors, and
  detached archive verifier under `toolset/`.

The v2 producer accepts only the seven-element deterministic-CBOR canonical-
record byte string. Source transport decoding, device authentication, payload
truth, dataset completeness, and autonomous-actuation suitability remain
outside the claim, as required by the draft.

## Normative coverage matrix

| Draft area | Implementation and executable evidence |
| --- | --- |
| §4.1–4.2 canonical-record boundary and deterministic CBOR | `trackone-ledger::v2::validate_canonical_record_v2`; ledger unit tests and v2 record vectors |
| §4.3 commitment tree and batches | `merkle_root_from_records`, `merkle_root_from_leaf_hashes`, `SegmentRecordV2::validate_detailed`; odd-leaf and multi-batch vector corpus |
| §4.4 interval formation, limits, recovery, durability | `V2LedgerProducer`; fake-clock tests for exact boundary, emit/suppress, reconfiguration, limits, restart recovery, and precedence |
| §4.5–4.6 artifact schema and chaining | v2 CDDL/JSON Schema, canonical encoder/decoder, epoch and successor vectors, negative predecessor vector |
| §5 portable bundles | `verify_manifest_v2.schema.json`; `openat2` with beneath/no-symlink/no-magic-link resolution and digest-bound reads |
| §6.2 RFC 3161 | OpenSSL `ts -verify` plus decoded SHA-256 and policy checks; signed epoch and successor `.tsr` fixtures |
| §6.5 verification result semantics | standardized executed/skipped identifiers, per-channel status, verifier policy, and public/partial/anchor-only scope |
| §7 disclosure classes | strict Class A, B, and C bundle fixtures in `toolset/vectors/verifiable-telemetry-canonical-cbor-v2` |
| §8 versioning | distinct v1/v2 manifest schemas and immutable commitment profile identifiers |
| §9 vectors | Rust CLI integration test, detached standard-library verifier, contract checker, and conformance archive workflow |

## Deployment profile

The baseline deployment is Linux with one active writer per ledger and a
PostgreSQL durable store initialized from
`crates/trackone-gateway/migrations/0001_v2_ledger.sql`. The database role must
be able to take transaction-scoped advisory locks and mutate the four v2
tables in one serializable transaction. A restart must use a new elapsed-clock
continuity identifier and invoke recovery before accepting telemetry.

RFC 3161 verification requires OpenSSL on `PATH`, a deployment trust-anchor
file passed with `--tsa-ca-file`, and the expected TSA policy passed with
`--tsa-policy`. The conformance fixture root is test-only and must not be used
as a production trust anchor.

## Verification

Run the supported repository gates:

```console
python3 toolset/ci/check_contracts.py
cargo test -p trackone-ledger --locked
cargo test -p trackone-gateway --features postgres-store --locked
cargo test -p trackone-evidence --locked
cargo clippy -p trackone-gateway --features postgres-store -- -D warnings
cargo clippy -p trackone-evidence --all-targets -- -D warnings
```

Successful verification is scoped only to the artifacts and checks reported
in the verifier result. It is not a claim of input completeness, physical
truth, or fitness for automated sanctions or actuation.
