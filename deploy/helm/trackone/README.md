# TrackOne Helm chart (published OCI artifact workflow)

This chart now defaults to the published-artifact deployment model, and tagged
releases publish the chart itself as an OCI artifact in GHCR.

## Recommended workflow: install the published chart artifact

Use the published chart for normal deployments:

```bash
helm upgrade --install trackone oci://ghcr.io/bilalobe/trackone/charts/trackone \
  --version <release-version> \
  --namespace trackone \
  --create-namespace \
  --set postgres.auth.existingSecret=<your-postgres-secret>
```

For example, release tag `v0.1.0-alpha.15` publishes chart version
`0.1.0-alpha.15`.

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
  -f deploy/helm/trackone/values-published.yaml \
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
only when you explicitly want local images and build jobs again.

Typical flow:

```bash
eval "$(minikube -p ${MINIKUBE_PROFILE:-minikube} docker-env)"
docker build -t trackone/ots-calendar:local -f deploy/docker/calendar/Dockerfile deploy/docker/calendar
docker build -t trackone/gateway:local -f deploy/docker/gateway/Dockerfile .
docker build -t trackone/core:local -f deploy/docker/core/Dockerfile .
docker build -t trackone/constants:local -f deploy/docker/constants/Dockerfile .
docker build -t trackone/pod-fw:local -f deploy/docker/pod-fw/Dockerfile .
helm upgrade --install trackone deploy/helm/trackone \
  -f deploy/helm/trackone/values-local.yaml
```

`values-local.yaml` explicitly opts in to the stock local Postgres credentials.

## Maintainer workflow: publish the chart artifact

Tagged releases publish the chart to:

```text
oci://ghcr.io/bilalobe/trackone/charts/trackone
```

The release workflow packages `deploy/helm/trackone` with:

- chart `version = ${GITHUB_REF_NAME#v}`
- chart `appVersion = ${GITHUB_REF_NAME#v}`

That keeps the install version aligned with the release tag instead of the
checked-in `Chart.yaml` version.

## Generated runtime config

The chart generates and manages these runtime config objects:

- `ConfigMap/trackone-gateway-config` for non-secret gateway config such as `OTS_CALENDARS`
- `Secret/trackone-gateway-env` for sensitive gateway config such as `DATABASE_URL`
- `Secret/postgres-auth` for Postgres bootstrap credentials

The values still live in `values.yaml` and any overlays, but the pods now consume
them via `configMapRef` / `secretKeyRef` instead of inline `env.value` entries.

If you already manage non-secret gateway config elsewhere, set
`gateway.existingConfigMap` and the chart will reuse that ConfigMap instead of
creating `trackone-gateway-config`. That ConfigMap must define an `OTS_CALENDARS` key to match the environment consumed via `envFrom`.

If you already manage sensitive gateway config elsewhere, set
`gateway.existingSecret` and the chart will reuse that Secret instead of
creating `trackone-gateway-env`. That Secret must define a `DATABASE_URL` key to match the environment consumed via `secretKeyRef`.

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
