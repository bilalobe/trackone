# TrackOne

TrackOne is a beta Rust workspace for low-power telemetry, framed ingest,
deterministic ledger artifacts, evidence verification, and pod firmware
helpers. The workspace is the evidence plane: lifecycle, onboarding, and fleet
orchestration systems may provide inputs, but canonical telemetry evidence is
owned and verified here.

## Workspace map

The source tree makes the dependency direction explicit:

| Layer | Packages | Purpose |
| --- | --- | --- |
| Reusable libraries | `trackone-core`, `trackone-constants`, `trackone-ingest`, `trackone-ledger`, `trackone-ots`, `trackone-rfc3161`, `trackone-sensorthings`, `trackone-pod-fw` | Protocol, framing, commitment, timestamp verification, projection, and firmware logic |
| Applications | `trackone-evidence`, `trackone-gateway-svc` | Supported v2 verifier/compactor and deployable v2 gateway |

Reusable crates depend only on reusable crates. Applications compose reusable
crates at the edge. These rules are checked by
[`just boundaries`](justfile) and
[`toolset/ci/check_workspace_boundaries.py`](toolset/ci/check_workspace_boundaries.py).

## Data and evidence flow

The normal path is:

```text
pod-fw -> ingest -> gateway-svc -> ledger -> evidence verifier
                                      \-> SensorThings projection
                                      \-> OTS/TSA publication edges
```

Canonical evidence is CBOR-backed. JSON and SensorThings outputs are
read-only projections, and OTS/TSA responses attest to already-created
artifacts rather than changing their bytes. The current v1 and draft-09 v2
commitment contracts are represented by checked-in schemas, CDDL, vectors, and
detached-verifier fixtures under [`toolset/`](toolset/).

## Requirements

- Rust `1.93` with the workspace's locked dependency set
- `just` for the supported local matrix
- Python 3 for contract and detached-verifier tooling
- Helm and `kubectl` for deployment-template checks
- Docker or another OCI builder for local image checks

## Quick start

From the repository root:

```bash
just boundaries
just fmt-check
just test
just clippy
just build-production
```

The curated matrix includes the `no_std` ingest path, supported `std`/AEAD
features, and ignored commitment vectors. For a faster workspace smoke check,
use:

```bash
cargo check --workspace --locked
cargo build --workspace --release --locked
```

## Evidence application

`trackone-evidence` is the supported v2 verifier and deterministic compactor.
Verify a directory bundle with:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures/corrected-epoch-class-a \
  --tsa-ca-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-root.pem \
  --tsa-crls-file toolset/vectors/verifiable-telemetry-canonical-cbor-v2/trust/tsa-crls.pem \
  --tsa-policy 1.3.6.1.4.1.55555.1 \
  --tsa-signer-cert-sha256 14ab98cafe09d9d1d01562af42d69a904b01023d9cd5b03bd07e5779710c8014
```

Use `--json` for machine-readable summaries. `compact` emits the active
manifest-v3 gzip carrier, and `verify --archive FILE` verifies that carrier.
Manifest v2 remains read-only input for the same v2 commitment profile, and
the v1 commitment contract remains covered by its schemas and conformance
vectors. The legacy v1 verifier/export CLI and the old
`verify-v2`/`compact-v2` command names are intentionally not part of the
supported application surface.

## Gateway service

`trackone-gateway-svc` owns the draft-09 v2 HTTP runtime, PostgreSQL state,
migrations, elapsed-time producer, idempotency handling, and RFC 3161
submission. The binary is `trackone-v2-gateway`.

Required environment variables:

- `TRACKONE_DATABASE_URL`
- `TRACKONE_INGEST_BEARER_TOKEN` (32–256 visible ASCII characters)
- `TRACKONE_LEDGER_ID` (32 lowercase hexadecimal characters)
- `TRACKONE_SITE_ID`
- `TRACKONE_TSA_URL`
- `TRACKONE_TSA_CA_FILE`
- `TRACKONE_TSA_CRLS_FILE`
- `TRACKONE_TSA_POLICY_OID`
- `TRACKONE_TSA_SIGNER_CERT_SHA256`

Optional runtime settings include `TRACKONE_BIND` (default
`0.0.0.0:8080`), `TRACKONE_EMPTY_MODE`, `TRACKONE_INTERVAL_MS`,
`TRACKONE_BATCH_RECORD_LIMIT`, `TRACKONE_RECORD_LIMIT`, and
`TRACKONE_SIZE_LIMIT_BYTES`. HTTP admission is bounded by
`TRACKONE_MAX_BATCH_RECORDS` (default 1,000) and
`TRACKONE_MAX_ADMISSION_BYTES` (default 4 MiB).
`TRACKONE_INGEST_BEARER_TOKEN_PREVIOUS` enables a two-token rotation window.
PostgreSQL uses verified TLS by default
(`TRACKONE_POSTGRES_TLS_MODE=verify-full`); optionally supply
`TRACKONE_POSTGRES_CA_FILE` for a private CA. Plaintext requires the explicit
development-only value `TRACKONE_POSTGRES_TLS_MODE=disable`.

Run the service after supplying those values:

```bash
cargo run --locked -p trackone-gateway-svc --bin trackone-v2-gateway
```

The HTTP surface is intentionally small:

- `GET /healthz` returns the service/profile health document.
- `POST /v2/records` accepts canonical record CBOR with
  `Content-Type: application/cbor`, a required `Idempotency-Key` header, and
  `Authorization: Bearer <token>`.
- `POST /v2/record-batches` atomically accepts a definite CBOR array of exact
  record byte strings, optionally with `Content-Encoding: gzip`, and requires
  the same bearer authentication. `/healthz` remains unauthenticated.

Evidence manifest v3 and `trackone-evidence compact` provide deterministic
`application/vnd.trackone.evidence-bundle.v3+gzip` carriers with packed Class
A records. `verify --archive` applies the same v2 verification after
bounded safe extraction; manifest v2 remains readable. Manifest v3 carries
only verification-critical discovery references and producer
`present`/`pending` claims. Verifier-authored result v2 reports scoped
success, partial, or failure without duplicating TSA diagnostics or
`segment_root`.

The service's Dockerfile, migrations, and sole runtime deployment surface
(the Helm chart) are owned by
[`apps/trackone-gateway-svc/deploy/`](apps/trackone-gateway-svc/deploy/).
The retained Kustomize tree renders build-check Jobs only.

## Deployment

Tagged releases publish the Helm chart to:

```text
oci://ghcr.io/bilalobe/trackone/charts/trackone
```

Install a published chart with an existing Postgres secret:

```bash
helm upgrade --install trackone \
  oci://ghcr.io/bilalobe/trackone/charts/trackone \
  --version <release-version> \
  --namespace trackone \
  --create-namespace \
  --set postgres.auth.existingSecret=<your-postgres-secret>
```

The bundled PostgreSQL workload is TLS-only by default; the chart retains a
private CA/server keypair and mounts the CA into the gateway automatically.
The chart README documents deployment-managed certificate overrides,
private-image pulls, generated runtime ConfigMaps and Secrets, and the
explicit plaintext local/Minikube override. Reusable build-only Dockerfiles
remain under [`deploy/docker/`](deploy/docker/).

## Contract and conformance tooling

- [`toolset/unified/`](toolset/unified/) contains canonical schemas and CDDL.
- [`toolset/vectors/`](toolset/vectors/) contains v1, v2, and negative fixtures.
- [`toolset/anchoring/`](toolset/anchoring/) contains anchor-evidence state and
  receipt checks.
- [`toolset/independent-verifier/`](toolset/independent-verifier/) builds and
  verifies self-contained conformance archives without importing repository
  runtime code.

The release workflow packages ten publishable Cargo artifacts and one Helm
chart. The unpublished Python binding is checked in the Rust matrix but is
excluded from publication and conformance package counts.

## Repository guide

- [`crates/`](crates/) — reusable protocol and evidence-plane libraries
- [`apps/`](apps/) — deployable/operator-facing packages
- [`bindings/`](bindings/) — optional language adapters
- [`docs/`](docs/) — implementation and conformance notes
- [`adr/`](adr/) — architecture decisions and supersession history
- [`CHANGELOG.md`](CHANGELOG.md) — manually curated release history

When a change crosses a package boundary, update the owning README, relevant
ADR, and release/deployment references together. Keep canonical artifact
behavior in the reusable crates and keep lifecycle/control-plane behavior out
of the evidence path.
