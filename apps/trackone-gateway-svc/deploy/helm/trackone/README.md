# TrackOne Helm chart (published OCI artifact workflow)

This chart now defaults to the published-artifact deployment model, and tagged
releases publish the chart itself as an OCI artifact in GHCR.

Unless a command says otherwise, run the examples from the repository root.
The chart is application-owned at
`apps/trackone-gateway-svc/deploy/helm/trackone`; reusable Rust build images
remain at `deploy/docker/`.

## Recommended workflow: install the published chart artifact

Use the published chart for normal deployments:

```bash
helm upgrade --install trackone oci://ghcr.io/bilalobe/trackone/charts/trackone \
  --version <release-version> \
  --namespace trackone \
  --create-namespace \
  --set postgres.auth.existingSecret=<your-postgres-secret>
```

For example, release tag `v0.1.0-beta.5` publishes chart version
`0.1.0-beta.5`.

The base [values.yaml](values.yaml)
inside that OCI chart assumes:

- `gateway` and `ots-calendar` run from registry images
- in-cluster build jobs are disabled
- persistent storage is enabled for Postgres and the OTS calendar
- chart-managed Postgres accepts TLS network connections only and uses a
  retained, chart-generated private CA unless an existing TLS Secret is named
- runtime config is generated into Kubernetes config objects instead of being embedded inline in pod specs

If your GHCR images are private, add the published overlay from this repo:

```bash
helm upgrade --install trackone oci://ghcr.io/bilalobe/trackone/charts/trackone \
  --version <release-version> \
  --namespace trackone \
  --create-namespace \
  -f apps/trackone-gateway-svc/deploy/helm/trackone/values-published.yaml \
  --set postgres.auth.existingSecret=<your-postgres-secret>
```

The chart now fails fast if you leave the stock `trackone/trackone/trackone`
Postgres credentials in place while using the generated Postgres Secret. For
non-local installs, either:

- set `postgres.auth.existingSecret`
- or override `postgres.auth.database`, `postgres.auth.username`, and `postgres.auth.password`

Enabling the gateway also requires a bearer credential of 32–256 visible ASCII
characters. Set `gateway.auth.bearerToken` when the chart manages the gateway
Secret, or provide `TRACKONE_INGEST_BEARER_TOKEN` in
`gateway.existingSecret`. `gateway.auth.previousBearerToken` (or the matching
optional Secret key) supports a two-token rotation window.

The chart-managed PostgreSQL workload has TLS enabled by default. When
`postgres.tls.existingSecret` is empty, Helm generates `ca.crt`, `tls.crt`, and
`tls.key` in `Secret/trackone-postgres-tls`; subsequent upgrades reuse that
Secret rather than rotating the CA unexpectedly. The server certificate is
valid for `postgres` and its namespace-qualified Kubernetes service names.
PostgreSQL uses TLS 1.2 or newer, SCRAM-SHA-256 host authentication, and rejects
plaintext network connections. To supply deployment-managed material instead,
set `postgres.tls.existingSecret` to a `kubernetes.io/tls` Secret containing
those three keys.

## Optional local build-check override

Use the local chart directory and
[values-local.yaml](values-local.yaml)
only when you explicitly want local build Jobs. The local override keeps the
gateway and OTS calendar disabled unless you provide supported images and opt
into those Helm workloads yourself. The separate Kustomize tree is build-only;
Helm is the sole runtime deployment surface.

Typical flow:

```bash
eval "$(minikube -p ${MINIKUBE_PROFILE:-minikube} docker-env)"
docker build -t trackone/core:local -f deploy/docker/core/Dockerfile .
docker build -t trackone/constants:local -f deploy/docker/constants/Dockerfile .
docker build -t trackone/pod-fw:local -f deploy/docker/pod-fw/Dockerfile .
helm upgrade --install trackone apps/trackone-gateway-svc/deploy/helm/trackone \
  -f apps/trackone-gateway-svc/deploy/helm/trackone/values-local.yaml
```

`values-local.yaml` explicitly opts in to the stock local Postgres credentials
and disables both sides of PostgreSQL TLS. This is a development-only exception;
enabling the gateway with that overlay uses
`gateway.postgres.tlsMode=disable`.
The pod firmware build job runs the local image as a release-mode production
build with default features disabled.

## Maintainer workflow: publish the chart artifact

Tagged releases publish the chart to:

```text
oci://ghcr.io/bilalobe/trackone/charts/trackone
```

The release workflow packages
`apps/trackone-gateway-svc/deploy/helm/trackone` with:

- chart `version = ${GITHUB_REF_NAME#v}`
- chart `appVersion = ${GITHUB_REF_NAME#v}`

That keeps the install version aligned with the release tag instead of the
checked-in `Chart.yaml` version.

Validate the chart locally with:

```bash
helm lint apps/trackone-gateway-svc/deploy/helm/trackone \
  --set postgres.auth.existingSecret=postgres-auth
helm template trackone apps/trackone-gateway-svc/deploy/helm/trackone \
  --values apps/trackone-gateway-svc/deploy/helm/trackone/values-local.yaml

helm template trackone apps/trackone-gateway-svc/deploy/helm/trackone \
  --set postgres.auth.existingSecret=postgres-auth \
  --set gateway.enabled=true \
  --set-string gateway.auth.bearerToken=0123456789abcdef0123456789abcdef \
  --set-string gateway.env.tsaSignerCertSha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --set-file gateway.env.tsaCaPem=/path/to/tsa-ca.pem \
  --set-file gateway.env.tsaCrlsPem=/path/to/tsa-crls.pem
```

## Generated runtime config

The chart generates and manages these runtime config objects:

- `ConfigMap/trackone-gateway-config` for non-secret gateway, PostgreSQL TLS,
  admission-limit, and TSA policy settings
- `Secret/trackone-gateway-env` for `TRACKONE_DATABASE_URL`, bearer tokens,
  RFC 3161 validation material, and an optional private PostgreSQL CA
- `Secret/postgres-auth` for Postgres bootstrap credentials
- `Secret/trackone-postgres-tls` for the retained generated PostgreSQL CA and
  server keypair, unless `postgres.tls.existingSecret` is set
- `ConfigMap/trackone-postgres-tls-config` for TLS-only host authentication

The values still live in `values.yaml` and any overlays, but the pods now consume
them via `configMapRef` / `secretKeyRef` instead of inline `env.value` entries.

If you already manage non-secret gateway config elsewhere, set
`gateway.existingConfigMap` and the chart will reuse that ConfigMap instead of
creating `trackone-gateway-config`. It must define
`TRACKONE_POSTGRES_TLS_MODE`, `TRACKONE_LEDGER_ID`, `TRACKONE_SITE_ID`,
`TRACKONE_TSA_URL`, `TRACKONE_TSA_POLICY_OID`,
`TRACKONE_TSA_SIGNER_CERT_SHA256`, `TRACKONE_MAX_BATCH_RECORDS`, and
`TRACKONE_MAX_ADMISSION_BYTES`, plus the other enabled runtime settings shown
in `values.yaml`. The chart defaults the admission bounds to 1,000 records and
4 MiB; the binary rejects values above 10,000 records or 16 MiB. When the
chart-managed database uses TLS, the ConfigMap must also set
`TRACKONE_POSTGRES_CA_FILE=/var/run/trackone-postgres/ca.pem`; the chart still
mounts the managed CA at that path.

If you already manage sensitive gateway config elsewhere, set
`gateway.existingSecret` and the chart will reuse that Secret instead of
creating `trackone-gateway-env`. That Secret must define
`TRACKONE_DATABASE_URL`, `TRACKONE_INGEST_BEARER_TOKEN`, `tsa-ca.pem`, and
`tsa-crls.pem`; it may also define `TRACKONE_INGEST_BEARER_TOKEN_PREVIOUS`,
`tsa-intermediates.pem`, and, for an external database, `postgres-ca.pem`. Set
the corresponding
`gateway.existingSecretHasTsaIntermediates` and
`gateway.existingSecretHasPostgresCa` flags when the optional mounted files are
present. When the chart manages the Secret, set `gateway.env.tsaCaPem` and
`gateway.env.tsaCrlsPem` (preferably with `--set-file`), optionally set
`gateway.env.tsaIntermediatesPem`, and configure the TSA URL, policy OID, and
SHA-256 DER signer-certificate pin as `gateway.env.tsaSignerCertSha256`.

The gateway defaults to `gateway.postgres.tlsMode=verify-full`. When the
chart-managed PostgreSQL workload is enabled, its CA is mounted into the
gateway automatically. `gateway.postgres.caPem` (preferably with `--set-file`)
is for an external PostgreSQL deployment; disable the bundled database with
`postgres.enabled=false` in that case. The chart rejects mismatched managed
configurations: `postgres.tls.enabled=true` requires `verify-full`, while the
development-only `postgres.tls.enabled=false` requires `disable`.

If you already manage Postgres bootstrap credentials elsewhere, set
`postgres.auth.existingSecret` and the chart will reuse that Secret instead of
creating `postgres-auth`. That Secret must contain, at minimum, the keys
`POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`, since the Postgres
pod consumes them via `envFrom`.

For deployment-managed PostgreSQL certificates, set
`postgres.tls.existingSecret`. That Secret must contain `ca.crt`, `tls.crt`,
and `tls.key`; `tls.crt` must cover the `postgres` hostname used by
`gateway.env.databaseUrl`. After rotating an existing TLS Secret, restart both
the PostgreSQL StatefulSet and gateway Deployment so they reload the keypair
and trust anchor. To rotate a chart-generated certificate, delete
`trackone-postgres-tls`, run a Helm upgrade, and restart both workloads during
the same maintenance window.

### Private GHCR images

If your GHCR images are private, create an `imagePullSecret` in the target namespace and reference it via
`imagePullSecrets` in your values file or the published overlay:

```bash
kubectl -n trackone create secret docker-registry ghcr-creds \
  --docker-server=ghcr.io \
  --docker-username=<USER> \
  --docker-password=<TOKEN> \
  --docker-email=<EMAIL>
```
