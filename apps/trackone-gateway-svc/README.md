# trackone-gateway-svc

Deployable VTL gateway application. It owns the HTTP handoff,
PostgreSQL durability and migrations, elapsed-time producer state machine,
idempotency handling, RFC 3161 submission, and the `trackone-vtl-gateway`
binary.

Reusable protocol and commitment rules remain in
[`trackone-ledger`](../../crates/trackone-ledger/README.md). OTS verification
and optional Python adapters live in their own packages, so this service has
no binding-layer dependency.

## Runtime configuration

Both `trackone-vtl-gateway` and `trackone-vtl-export` use Clap for typed options,
environment variables, and generated `--help` / `--version` output. Existing
`TRACKONE_*` names and runtime defaults are preserved. Command-line options
override environment values; omitted options use their defaults. Invalid
values fail startup instead of silently selecting a default.

Run `cargo run --locked -p trackone-gateway-svc --bin trackone-vtl-gateway -- --help`
to see every setting, its environment variable, and its default. Most option
names correspond to their environment suffix, for example
`--bind` / `TRACKONE_BIND` and `--tsa-max-attempts` /
`TRACKONE_TSA_MAX_ATTEMPTS`. The database connection is `--db-url`
(`--database-url` is an alias), backed by `TRACKONE_DATABASE_URL`.
Credential and database URL environment values are hidden in help output.

The binary requires:

- `TRACKONE_DATABASE_URL`
- `TRACKONE_INGEST_BEARER_TOKEN` — 32–256 visible ASCII characters
- `TRACKONE_LEDGER_ID` — 32 lowercase hexadecimal characters
- `TRACKONE_SITE_ID`
- `TRACKONE_TSA_URL`
- `TRACKONE_TSA_CA_FILE` — deployment trust anchors
- `TRACKONE_TSA_CRLS_FILE` — retained complete base CRLs
- `TRACKONE_TSA_POLICY_OID`
- `TRACKONE_TSA_SIGNER_CERT_SHA256` — 64 lowercase hexadecimal characters,
  calculated over the complete DER TSA signer certificate

Optional settings are `TRACKONE_BIND` (default `0.0.0.0:8080`),
`TRACKONE_EMPTY_MODE` (`suppress` or `emit`), `TRACKONE_INTERVAL_MS`,
`TRACKONE_BATCH_RECORD_LIMIT`, `TRACKONE_RECORD_LIMIT`, and
`TRACKONE_SIZE_LIMIT_BYTES`. Admission bounds use
`TRACKONE_MAX_BATCH_RECORDS` (default 1,000; hard maximum 10,000) and
`TRACKONE_MAX_ADMISSION_BYTES` (default 4,194,304; hard maximum 16,777,216).
`TRACKONE_TSA_INTERMEDIATES_FILE` supplies a
deployment-managed intermediate bundle when the TSA path requires one.
`TRACKONE_TSA_MAX_FUTURE_SKEW_SECONDS` sets the maximum accepted lead of the
TSA-signed `genTime` over the gateway clock. It defaults to `0` and accepts
integer seconds from `0` through `3600`; invalid values fail gateway startup.
`TRACKONE_INGEST_BEARER_TOKEN_PREVIOUS` optionally keeps the prior credential
valid during a bounded two-token rotation window.

`TRACKONE_INTERVAL_MS` defaults to `60000` and must be positive.
`TRACKONE_BATCH_RECORD_LIMIT` defaults to `1024` and must be a power of two
through `2^63`. Optional record and size limits must be positive when supplied.
TSA workers use `TRACKONE_TSA_WORKER_CONCURRENCY` (default `2`, range `1–16`),
`TRACKONE_TSA_MAX_ATTEMPTS` (default `20`, range `1–1000`),
`TRACKONE_TSA_RETRY_INITIAL_MS` (default `5000`), and
`TRACKONE_TSA_RETRY_MAX_MS` (default `300000`). Retry delays must be positive,
ordered from initial to maximum, and no greater than `86400000` milliseconds.
These settings, ingest credentials, grants JSON, and TSA validation material
are checked before connecting to PostgreSQL.

PostgreSQL uses hostname-verified TLS by default
(`TRACKONE_POSTGRES_TLS_MODE=verify-full`). Set
`TRACKONE_POSTGRES_CA_FILE` when a private CA must be added to the platform
trust store. Plaintext is accepted only when
`TRACKONE_POSTGRES_TLS_MODE=disable` is explicitly selected for development.
The app-owned Helm chart enables TLS and TLS-only host authentication on its
bundled PostgreSQL workload and mounts that workload's CA into the gateway
automatically.

TSA configuration and validation material are loaded and validated at
startup. Stamping derives one SHA-256 digest from the authoritative artifact,
submits into a sibling staging file, applies the strict archived-token profile
to the returned bytes, and only then publishes the `.tsr` without overwriting
an existing final path. The internal result retains the asserted generation
time, serial number, accuracy, policy identifier, and signer fingerprint.

Start it locally after supplying the required values:

```bash
cargo run --locked -p trackone-gateway-svc --bin trackone-vtl-gateway
```

## Timestamp queue

Admission success acknowledges durable occurrence and sealed-segment persistence.
It does not wait for the TSA. Startup binds the listener before starting workers,
so an existing backlog or TSA outage does not delay listener availability.
The additive queue migration is applied automatically and can be run repeatedly
against a database using the current commitment profile.

Workers use separate PostgreSQL connections and claim one due segment at a time.
The default pool contains two workers. Retry metadata is durable: attempt count,
next attempt, last error (at most 512 characters), and a five-minute claim lease.
A crash before attachment or ambiguous remote result can resubmit the same digest;
the first committed verified response is retained without replacement. A completed
segment never changes its artifact bytes, digest, or predecessor.

| Environment variable | Default | Accepted values |
| --- | --- | --- |
| `TRACKONE_TSA_WORKER_CONCURRENCY` | `2` | 1–16 |
| `TRACKONE_TSA_MAX_ATTEMPTS` | `20` | 1–1000 |
| `TRACKONE_TSA_RETRY_INITIAL_MS` | `5000` | 1–86400000 |
| `TRACKONE_TSA_RETRY_MAX_MS` | `300000` | Initial delay through 86400000 |

After failed attempt n, delay is `min(initial × 2^(n−1), maximum)`.
Exhausted attempts become terminal `failed` jobs, including an expired final
claim. Changing the attempt limit does not requeue failed jobs. Database
outages trigger worker reconnects; PostgreSQL connection establishment has a
five-second timeout. SIGTERM/SIGINT stop new claims and let active bounded
submissions finish. Abrupt termination recovers via lease expiry.

See [ADR-067](../../adr/ADR-067-asynchronous-rfc3161-submission.md).

## HTTP surface

- `GET /v2/segments/{segment_number}/timestamp` requires the admission bearer
  token and reports the configured ledger's segment timestamp state. The JSON
  fields are `ledger_id`, `segment_number`, `artifact_sha256`, `state`,
  `attempt_count`, `next_attempt`, and `last_error`. Integer fields are decimal
  strings; timestamps are UTC RFC3339. State is `queued`, `failed` (terminal),
  or `attached`. Next attempt and last error are nullable. During a claim,
  next attempt indicates the recovery lease deadline. Invalid segment numbers
  return 400; missing segments return 404.
- `GET /healthz` is a public process-liveness check returning the active normative commitment-profile UUID. It performs no database query or producer lock acquisition.
- `GET /readyz` is a public evidence-pipeline readiness check described below.
- `POST /v2/records` accepts one canonical record as
  `application/cbor`. Every request must include `Idempotency-Key` and
  `Authorization: Bearer <token>`.
- `POST /v2/record-batches` accepts a shortest-form definite CBOR array of
  canonical-record byte strings as
  `application/vnd.trackone.record-batch.v1+cbor`. This route also accepts
  `Content-Encoding: gzip`; its idempotency digest covers the expanded
  envelope, so compressed and identity requests replay identically. Both POST
  routes require bearer authentication; `/healthz` and `/readyz` remain public.

Fresh admissions report `tsa_status: "queued"` for newly sealed segments and
`not_applicable` when no segment seals. Replays report `failed` if any referenced
segment failed, otherwise `queued` while any remain pending, otherwise `verified`.
A failed status lookup falls back to `queued` without revoking admission success.
The timestamp endpoint provides per-segment details. Export refuses queued and
failed segments until a verified response is retained.

Successful admissions return `201 Created`; an idempotent replay returns
`200 OK`. `Prefer: return=minimal` returns an empty success body with
`Preference-Applied`. Batch responses contain ordered admission runs and
sealed segment numbers. Invalid media or encoding receives 415, malformed
envelopes 400, invalid inner records 422, and configured limit violations 413.

The 60-second interval, `suppress` empty mode, and 1,024-record segment batch
limit are conservative defaults. Lower intervals reduce timestamp latency but
create more artifacts and finer disclosure boundaries; higher admission
limits reduce request overhead but increase the atomic resource domain.
Controlled TSAs should include the signer certificate and omit a root already
present in the configured trust archive. Received responses are never
rewritten, and valid historical responses with additional certificates remain
accepted.

## Owned assets and checks

The package owns its production [Dockerfile](deploy/Dockerfile), Helm runtime
chart, and PostgreSQL migration under `migrations/`. The local Kustomize tree
is retained only for reusable build-check Jobs and does not define runtime
gateway, Postgres, or OTS resources.

```bash
cargo test --locked -p trackone-gateway-svc
cargo build --locked -p trackone-gateway-svc --release --bin trackone-vtl-gateway
helm lint apps/trackone-gateway-svc/deploy/helm/trackone \
  --set postgres.auth.existingSecret=postgres-auth
```

## Authenticated evidence retrieval

Ledger-addressed evidence and immutable Class A/B/C disclosures are available
under `/v2/ledgers/{ledger_id}/segments/{segment_number}`. Set
`TRACKONE_DISCLOSURE_GRANTS_FILE` to a JSON secret containing scoped credentials;
omission disables access, and ingest credentials do not grant disclosure access.
See the [HTTP binding](../../docs/vtl-http-binding.md) for exact endpoints,
availability responses, grant configuration, fixtures, and independent retrieval.
Helm mounts an existing `grants.json` Secret through
`gateway.disclosure.existingSecret`. The additive snapshot migration runs at
startup; existing sealed segments are unchanged.

The exporter shares the gateway's `--db-url`, `--postgres-tls-mode`, and
`--postgres-ca-file` options and their environment bindings. Its existing
`--ledger-id`, `--segment-number`, `--class`, repeatable `--batch`, and
`--output` arguments are listed by `trackone-vtl-export --help`.

## Evidence-pipeline readiness and capacity

`GET /readyz` returns 200 when durable admission is available and 503 otherwise.
Its JSON contains `ready`, `admission_available`, `reasons`,
`database_available`, `producer_state`, `pipeline_degraded`,
`observed_at_unix_seconds`, `statistics`, `capacity`, and `counters`.
A single maintenance task checks the actual admission connection and producer every
five seconds. It seals overdue intervals in a preservation transaction before
publishing the observation, even when admission capacity is exhausted. Empty
intervals follow the configured `emit` or `suppress` policy. Idle ticks without
expired intervals do not change the ledger revision.

Readiness requests read the cached result without querying PostgreSQL. Observations
expire after fifteen seconds; statistics and database availability become `null`
when unknown. Availability can lag changes by a sampling interval. Each database
sample has a two-second statement timeout and a one-second database lock timeout.
If the producer is busy, its active operation services the pending maintenance and
sampling request before releasing the producer mutex. This gives the sampler an
opportunity under sustained admission traffic. A stuck operation still lets the
previous observation expire.

Readiness reasons are `database_unavailable`, `database_read_only`, `producer_inactive`,
`producer_recovery_required`, `producer_clock_unavailable`,
`producer_lock_poisoned`, `producer_revision_mismatch`, `producer_sealing_failed`,
`queue_capacity_exhausted`, `storage_capacity_exhausted`, `storage_unavailable`,
`observation_unavailable`, `observation_stale`, and `shutdown`.
Startup remains unready until the first sample. Clock continuity must be recovered
before admission; an unexpected concurrent writer requires reloading the producer.
A closed admission connection requires restarting the gateway; this change does
not introduce automatic reconnection. Shutdown makes readiness unavailable.
Liveness remains independent of all these conditions.
The database probe inherits the admission session's transaction settings and checks
`transaction_read_only`, so a session write freeze or a standby reports
`database_read_only` even when queries succeed. The next successful writable
observation clears that reason after the write freeze is lifted.

Statistics include `pending_timestamp_count`,
`oldest_pending_timestamp_age_seconds`, `last_successful_timestamp_attachment`,
`terminal_failed_segment_count`, `retrying_timestamp_count`, and
`retained_evidence_bytes`. Counts and byte totals are JSON integers; age is seconds,
and attachment time is UTC RFC3339. Pending includes leased jobs and delayed
retries. Empty-backlog age and absent attachment time are `null`. Queued retry
errors and terminal failures set `pipeline_degraded=true` without independently
making admission unavailable. A TSA outage therefore permits admission while local
capacity remains. Terminal failures require operator investigation; they are not
automatically requeued.

Optional Clap CLI/environment settings apply per ledger:

| CLI option | Environment variable | Default |
| --- | --- | --- |
| `--max-pending-timestamps` | `TRACKONE_MAX_PENDING_TIMESTAMPS` | Unlimited |
| `--max-retained-evidence-bytes` | `TRACKONE_MAX_RETAINED_EVIDENCE_BYTES` | Unlimited |

Values must be positive uint64 integers. `capacity` reports `used`, nullable
`limit`, and nullable `utilization` for pending timestamps and evidence bytes.
Evidence bytes count canonical records (open or sealed), sealed commitment
artifacts, and retained timestamp responses exactly once. They exclude PostgreSQL
row overhead, indexes, WAL, idempotency metadata, backups, and other ledgers. Allow
extra database storage for those costs; these limits are admission thresholds,
not measurements of physical disk space or hard storage quotas.

Admission checks current and projected usage within the ledger transaction. A
request reaching a limit exactly succeeds; a request exceeding it or arriving
while usage is already exhausted returns 503 with `ok=false`,
`admission_available=false`, and `error=queue_capacity_exhausted` or
`storage_capacity_exhausted`. A rejected admission transaction commits no records,
artifacts, revision change, or idempotency entry. Independent interval maintenance
can still advance the ledger and enqueue overdue segments, allowing timestamp
workers to drain them before admission is retried. Accepted idempotency keys still replay at
capacity, and conflicting bytes still return 409. Other producer/database failures
return 503 with `admission_available=false` and `error=producer_unavailable`.
Interval maintenance, recovery sealing, and verified timestamp attachment can exceed configured
thresholds to preserve previously accepted evidence. Readiness reports that
pressure and blocks new admission. Queue pressure clears as jobs attach or reach
terminal status; storage pressure requires increasing the configured allowance or
provisioning storage. This service adds no evidence deletion policy. Physical
PostgreSQL write failures still reject the entire admission transaction. A
PostgreSQL disk-full error (`53100`) reports `storage_unavailable` for both admission
and readiness, even when read queries succeed. That signal clears after a
successful durable producer write or timestamp attachment, or a process restart;
fix storage first, then submit directly or restart to restore readiness.

The additive migration records enqueue and attachment times without changing
commitment bytes. Legacy queued segments use migration time as an approximate
enqueue time. Historical verified responses retain an unknown attachment time;
`last_successful_timestamp_attachment` reflects only known attachment times.
Transactional accounting is backfilled from existing evidence and maintained for
record transfers and timestamp updates. Migration acquires table locks, so plan
for startup migration time on large ledgers.

Counters cover rejected admission HTTP requests (including authentication and
validation), successfully committed recoveries, sealing construction/persistence
failures, and committed terminal timestamp transitions (including final lease
exhaustion). Each rejected request counts once; stale worker completions do not
count again. Intentional capacity rejection is not a sealing failure. Counters
include `process_started_at_unix_seconds` and reset on process restart; durable
queue statistics survive restart. They describe events observed by this gateway,
not a cumulative history across processes.
