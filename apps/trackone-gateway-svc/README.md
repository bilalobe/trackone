# trackone-gateway-svc

Deployable draft-08 v2 gateway application. It owns the HTTP handoff,
PostgreSQL durability and migrations, elapsed-time producer state machine,
idempotency handling, RFC 3161 submission, and the `trackone-v2-gateway`
binary.

Reusable protocol and commitment rules remain in
[`trackone-ledger`](../../crates/trackone-ledger/README.md). OTS verification
and optional Python adapters live in their own packages, so this service has
no binding-layer dependency.

## Runtime configuration

The binary requires:

- `TRACKONE_DATABASE_URL`
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
`TRACKONE_SIZE_LIMIT_BYTES`. `TRACKONE_TSA_INTERMEDIATES_FILE` supplies a
deployment-managed intermediate bundle when the TSA path requires one.

TSA configuration and validation material are loaded and validated at
startup. Stamping derives one SHA-256 digest from the authoritative artifact,
submits into a sibling staging file, applies the strict archived-token profile
to the returned bytes, and only then publishes the `.tsr` without overwriting
an existing final path. The internal result retains the asserted generation
time, serial number, accuracy, policy identifier, and signer fingerprint.

Start it locally after supplying the required values:

```bash
cargo run --locked -p trackone-gateway-svc --bin trackone-v2-gateway
```

## HTTP surface

- `GET /healthz` returns `{ "ok": true, "profile": "...v2" }`.
- `POST /v2/records` accepts one canonical record as
  `application/cbor`. Every request must include an `Idempotency-Key`.

Successful admissions return `201 Created`; an idempotent replay returns
`200 OK`. Invalid media type, missing idempotency keys, conflicting keys, and
invalid records receive structured JSON error responses.

## Owned assets and checks

The package owns its production [Dockerfile](deploy/Dockerfile), Helm chart,
local Kustomize tree, and PostgreSQL migration under `migrations/`.

```bash
cargo test --locked -p trackone-gateway-svc
cargo build --locked -p trackone-gateway-svc --release --bin trackone-v2-gateway
helm lint apps/trackone-gateway-svc/deploy/helm/trackone
kubectl kustomize apps/trackone-gateway-svc/deploy/k8s/local/overlays/local
```
