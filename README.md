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
| Applications | `trackone-evidence`, `trackone-gateway-svc` | Supported verifier/export surface and deployable v2 gateway |
| Binding | `trackone-python` | Unpublished, opt-in legacy PyO3 adapter |

Reusable crates depend only on reusable crates. Applications compose reusable
crates at the edge. The binding may depend on reusable crates, but no library
or application depends on it. These rules are checked by
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
artifacts rather than changing their bytes. The current v1 and draft-08 v2
commitment contracts are represented by checked-in schemas, CDDL, vectors, and
detached-verifier fixtures under [`toolset/`](toolset/).

## Requirements

- Rust `1.93` with the workspace's locked dependency set
- `just` for the supported local matrix
- Python 3 for contract and detached-verifier tooling
- Helm and `kubectl` for deployment-template checks
- Docker or another OCI builder for local image checks

The Python binding is not a published product package. Build it only when
working on the legacy adapter and enable its `python` feature explicitly.

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
features, ignored commitment vectors, and the opt-in Python binding. For a
faster workspace smoke check, use:

```bash
cargo check --workspace --locked
cargo build --workspace --release --locked
```

## Evidence application

`trackone-evidence` is the supported verifier and export CLI. Verify a v1
bundle or export a day-scoped bundle with:

```bash
cargo run --locked -p trackone-evidence -- verify \
  --root out/site_demo \
  --facts out/site_demo/facts

cargo run --locked -p trackone-evidence -- export \
  --pipeline-dir out/site_demo \
  --evidence-repo /path/to/evidence \
  --site an-001 \
  --day 2025-10-07
```

Draft-08 v2 bundles use the separate policy surface:

```bash
cargo run --locked -p trackone-evidence -- verify-v2 \
  --root toolset/vectors/verifiable-telemetry-canonical-cbor-v2/fixtures/corrected-epoch-class-a \
  --allow-missing-tsa
```

Use `--json` for machine-readable summaries. Strict v1 verification can
require an attested OTS proof with `--policy-mode strict --require-ots`.

## Gateway service

`trackone-gateway-svc` owns the draft-08 v2 HTTP runtime, PostgreSQL state,
migrations, elapsed-time producer, idempotency handling, and RFC 3161
submission. The binary is `trackone-v2-gateway`.

Required environment variables:

- `TRACKONE_DATABASE_URL`
- `TRACKONE_LEDGER_ID` (32 lowercase hexadecimal characters)
- `TRACKONE_SITE_ID`
- `TRACKONE_TSA_URL`
- `TRACKONE_TSA_CA_FILE`
- `TRACKONE_TSA_POLICY_OID`
- `TRACKONE_TSA_SIGNER_CERT_SHA256`

Optional runtime settings include `TRACKONE_BIND` (default
`0.0.0.0:8080`), `TRACKONE_EMPTY_MODE`, `TRACKONE_INTERVAL_MS`,
`TRACKONE_BATCH_RECORD_LIMIT`, `TRACKONE_RECORD_LIMIT`, and
`TRACKONE_SIZE_LIMIT_BYTES`.

Run the service after supplying those values:

```bash
cargo run --locked -p trackone-gateway-svc --bin trackone-v2-gateway
```

The HTTP surface is intentionally small:

- `GET /healthz` returns the service/profile health document.
- `POST /v2/records` accepts canonical record CBOR with
  `Content-Type: application/cbor` and a required `Idempotency-Key` header.

The service's Dockerfile, migrations, Helm chart, and local Kustomize tree
are owned by [`apps/trackone-gateway-svc/deploy/`](apps/trackone-gateway-svc/deploy/).

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

The chart README documents private-image pulls, generated runtime ConfigMaps
and Secrets, and the optional local/Minikube override. Reusable build-only
Dockerfiles remain under [`deploy/docker/`](deploy/docker/).

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
