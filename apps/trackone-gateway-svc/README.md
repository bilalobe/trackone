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
- `GET /healthz` returns the active normative commitment-profile UUID.
- `POST /v2/records` accepts one canonical record as
  `application/cbor`. Every request must include `Idempotency-Key` and
  `Authorization: Bearer <token>`.
- `POST /v2/record-batches` accepts a shortest-form definite CBOR array of
  canonical-record byte strings as
  `application/vnd.trackone.record-batch.v1+cbor`. This route also accepts
  `Content-Encoding: gzip`; its idempotency digest covers the expanded
  envelope, so compressed and identity requests replay identically. Both POST
  routes require bearer authentication; `/healthz` remains public.

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
