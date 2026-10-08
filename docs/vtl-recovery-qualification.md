# VTL gateway recovery qualification

Issue #324 is qualified by a controlled run against the PostgreSQL-backed gateway,
its durable timestamp workers, and two evidence verification implementations.
The run injects process failures at selected persistence boundaries and compares
surviving data against an uploader journal stored outside the gateway.

## Run locally

Use Linux, Python 3.10+, the workspace Rust toolchain, OpenSSL 3, curl with TLS
1.3, and Docker daemon access. Cargo dependencies and `postgres:17-alpine` must
be cached or downloadable. The runner needs local listeners and temporary disk
space. It creates disposable database containers; it does not use a deployment
database or exhaust host storage.

```bash
python3 toolset/acceptance/run_vtl_recovery_qualification.py \
  --output /tmp/vtl-recovery-qualification
```

Choose a new output directory for each run. Qualification binaries are built in
`target/recovery-qualification/`, with `recovery-qualification` enabled. Normal
builds exclude the pause hooks and controlled clock. Controls are private local
files, with no HTTP administration endpoint. The runner kills actual gateway
processes at signaled boundaries, rather than estimating their timing with sleeps.

## Demonstrated behavior

The mandatory inventory covers precommit, committed-but-unanswered, and
acknowledged admissions; artifact construction; segment insertion and record
transfer; timestamp attachment before and after commit; failed admission,
sealing, and timestamp transactions; actual PostgreSQL ENOSPC; elapsed-clock
forward movement, backward discontinuity, and continuity changes; lost admission
responses; terminated database sockets; PostgreSQL process crash; TSA network
outage; and restoration into a fresh database and gateway.

The storage test fills a bounded Docker tmpfs tablespace containing ledger
relations. PGDATA and WAL remain on separate normal storage. Its passing evidence
requires a filesystem-full observation, a PostgreSQL ENOSPC error, rejection of
the failing admission, and successful recovery after removing the fixture filler.
It does not assert that a configured evidence capacity limit is physical ENOSPC.

Record checks compare multisets, including repeated identical records within a
batch and identical records admitted under separate keys. Retried keys must retain
one committed upload. Committed uploads with a lost response are tracked separately
from client-observed success. Every observed sealed artifact and attached TSA
response must remain byte-identical through subsequent checks.

Segment checks require contiguous serials, matching predecessor hashes and producer
state, ordered record ordinals, committed record counts, and recorded close reasons.
Restart recovery may add an empty recovery artifact even in suppress mode; that is
an explicit protocol closure, not an unexplained gap or duplicate.

Every scenario finishes by recovering open records, completing timestamps,
exporting every sealed segment as Class A, and checking the exports through the
independent Python HTTPS verifier and the Rust evidence CLI. Pending timestamps
cannot count as successful final evidence. Crash lease expiry is accelerated by
explicit fixture database updates whose prior lease state is recorded.

## Evidence and publication

`report.json` is the versioned machine-readable qualification result. It contains
the implementation base commit, dirty worktree state, source hashes, build feature
set, commitment profile UUID read from produced artifacts, tool and database image
identities, mandatory scenario inventory, fault observations, occurrence counts,
invariant conclusions, and links to verification reports. A dirty local run is
identified by its source hashes and cannot be presented as qualification of only
its base commit.

Each scenario retains uploader journals, reached crash hooks, baseline and final
database observations, gateway logs, exported bundles, HTTPS request logs, lease
adjustments, and reports from both verifiers. Global evidence includes exact TSA
queries and responses, public trust inputs, database diagnostics, and `SHA256SUMS`.
Credentials, CA signing keys, TSA signing keys, and temporary database dumps are
not published. A failing run retains its report and diagnostics and returns a
nonzero exit status. Missing or unobserved scenarios cannot pass qualification.

CI runs the full suite after the Rust and contract jobs and uploads
`vtl-recovery-qualification-<commit>` for 30 days, including failures. The
conformance archive requires this job to succeed. Source changes during a run
invalidate qualification; rerun after all implementation edits are complete.

The demonstrated claims cover the recorded process, PostgreSQL, network, and clock
failure conditions. Physical media corruption, hardware power loss, and durability
on storage that does not honor PostgreSQL synchronization are not qualified.
