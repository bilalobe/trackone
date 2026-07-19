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

For example, release tag `v0.1.0-beta.4` publishes chart version
`0.1.0-beta.4`.

The base [values.yaml](values.yaml)
inside that OCI chart assumes:

- `gateway` and `ots-calendar` run from registry images
- in-cluster build jobs are disabled
- persistent storage is enabled for Postgres and the OTS calendar
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

## Optional legacy local / Minikube override

Use the local chart directory and
[values-local.yaml](values-local.yaml)
only when you explicitly want local build jobs again. The beta.2 local override
keeps the gateway and OTS calendar disabled unless you provide supported images
and opt into those workloads yourself.

Typical flow:

```bash
eval "$(minikube -p ${MINIKUBE_PROFILE:-minikube} docker-env)"
docker build -t trackone/core:local -f deploy/docker/core/Dockerfile .
docker build -t trackone/constants:local -f deploy/docker/constants/Dockerfile .
docker build -t trackone/pod-fw:local -f deploy/docker/pod-fw/Dockerfile .
helm upgrade --install trackone apps/trackone-gateway-svc/deploy/helm/trackone \
  -f apps/trackone-gateway-svc/deploy/helm/trackone/values-local.yaml
```

`values-local.yaml` explicitly opts in to the stock local Postgres credentials.
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
helm lint apps/trackone-gateway-svc/deploy/helm/trackone
helm template trackone apps/trackone-gateway-svc/deploy/helm/trackone \
  --values apps/trackone-gateway-svc/deploy/helm/trackone/values-local.yaml
```

## Generated runtime config

The chart generates and manages these runtime config objects:

- `ConfigMap/trackone-gateway-config` for non-secret gateway config such as `OTS_CALENDARS`
- `Secret/trackone-gateway-env` for `TRACKONE_DATABASE_URL` and the RFC 3161 trust root
- `Secret/postgres-auth` for Postgres bootstrap credentials

The values still live in `values.yaml` and any overlays, but the pods now consume
them via `configMapRef` / `secretKeyRef` instead of inline `env.value` entries.

If you already manage non-secret gateway config elsewhere, set
`gateway.existingConfigMap` and the chart will reuse that ConfigMap instead of
creating `trackone-gateway-config`. That ConfigMap must define an `OTS_CALENDARS` key to match the environment consumed via `envFrom`.

If you already manage sensitive gateway config elsewhere, set
`gateway.existingSecret` and the chart will reuse that Secret instead of
creating `trackone-gateway-env`. That Secret must define
`TRACKONE_DATABASE_URL` and `tsa-ca.pem`. The latter is mounted as the RFC 3161
trust root. When the chart manages the Secret, set `gateway.env.tsaCaPem`
(preferably with `--set-file`) and configure the TSA URL and policy OID in
`gateway.env`.

If you already manage Postgres bootstrap credentials elsewhere, set
`postgres.auth.existingSecret` and the chart will reuse that Secret instead of
creating `postgres-auth`. That Secret must contain, at minimum, the keys
`POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD`, since the Postgres
pod consumes them via `envFrom`.

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
