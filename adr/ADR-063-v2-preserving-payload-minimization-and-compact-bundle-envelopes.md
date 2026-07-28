# ADR-063: V2-preserving payload minimization and compact bundle envelopes

**Status:** Accepted

## Context

The draft-08 implementation correctly preserves canonical record bytes and
segment commitments, but its first durable and portable interfaces amplify
payloads. PostgreSQL admissions rewrite the complete open interval, HTTP
clients can submit only one record per transaction, and Class A bundles repeat
each record as a separate filesystem artifact alongside optional projections.
These costs are implementation-envelope costs; changing the v2 record,
segment, Merkle, or predecessor definitions would invalidate existing proofs.

## Decision

The authoritative commitment profile remains
`verifiable-telemetry-canonical-cbor-v2`. Canonical records, segment CBOR,
Merkle ordering and splitting, embedded leaf hashes, predecessor hashes, and
received TSA and OTS proofs are immutable.

Durable writes use transition deltas. A transition identifies the previous
open-row count, each newly admitted record exactly once and its final open or
sealed destination, sealed-segment metadata, the next producer state, and the
idempotency result. Existing open rows move into a sealed segment with
`INSERT … SELECT`; ordinary admissions append and do not transmit or update
the predecessor. Full pending-TSA scans are startup recovery only. A live
admission stamps its returned sealed artifacts, while replay reads status for
only the segment numbers recorded by its idempotency result.

`POST /v2/record-batches` accepts a shortest-form, definite-length CBOR array
of byte strings under
`application/vnd.trackone.record-batch.v1+cbor`. Every byte string is one
unchanged canonical v2 record. Validation precedes mutation, the producer
takes one elapsed-clock snapshot, applies records in input order, and commits
with one CAS. The expanded canonical envelope is the idempotency identity, so
identity and gzip carriers replay equally. Batch admission is all-or-nothing;
sequential interval and size/record-limit closures remain observable as
ordered admission runs.

The default operational bounds are 1,000 records and 4 MiB expanded admission
bytes. Hard startup maxima are 10,000 records and 16 MiB. Individual
admissions use the same expanded-byte bound and remain uncompressed.
`Prefer: return=minimal` is available on both admission routes.

Verification-manifest envelope v3 adds an optional `records_pack`. A Class A
v3 manifest contains exactly one of `records` or `records_pack`. The pack is a
shortest-form definite CBOR array of byte strings containing exact record
bytes, ordered by the unchanged v2 leaf hash and then raw bytes, retaining
duplicates. Verification checks the pack digest, validates slices without
re-encoding, and applies the existing Class A leaf and Merkle comparisons.
Manifest v2 remains readable.

`application/vnd.trackone.evidence-bundle.v3+gzip` is the compact carrier.
Members are sorted and have zero time/owner metadata and fixed regular-file
modes; gzip has no filename and uses time zero. The minified v3 manifest keeps
the segment, disclosed predecessor, TSA response, paired OTS proof and
metadata, peer attestation, identity, anchoring claims, and disclosure class.
Operational projections and summaries are omitted. Extensions are opt-in.
Archive verification rejects non-regular members, links, devices, duplicate
or non-portable paths, over 10,000 members, compressed data over 64 MiB,
expanded data over 256 MiB, and members over 64 MiB.

Controlled TSAs should embed the signer certificate but omit an already
provisioned root. Verifiers continue to accept valid historical responses
containing additional certificates and never rewrite a received response.
The default closure cadence remains 60 seconds, `emptyMode=suppress`, and the
segment batch limit remains 1,000. Operators may tune interval and admission
limits, understanding that lower intervals reduce latency but increase
artifact overhead and disclosure granularity, while larger batches reduce
request overhead but enlarge atomic failure and resource domains.

## Deferred contracts

Binary hashes with integer labels, a normalized future segment encoding,
nonce-tail ingest frames, compact `EnvFact` variants, a new compact
commitment, and general framed-ingest encodings are deliberately not shipped.
Each changes bytes or interpretation and therefore requires its own versioned
contract, vectors, migration policy, and ADR.

## Consequences

Payload and write amplification fall without changing any v2 commitment or
existing proof. Batch clients gain atomic throughput, and compact carriers are
deterministic and bounded. Implementations must maintain two readable
manifest-envelope versions and enforce resource limits before allocating or
extracting untrusted carriers.
