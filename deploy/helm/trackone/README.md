# TrackOne Helm chart (published-artifact defaults)

This chart now defaults to the published-artifact deployment model.

## Default workflow: published artifacts

The base [values.yaml](/home/beb/GolandProjects/trackone/deploy/helm/trackone/values.yaml) assumes:

- `gateway` and `ots-calendar` run from registry images
- in-cluster build jobs are disabled
- persistent storage is enabled for Postgres and the OTS calendar
- runtime config is generated into Kubernetes config objects instead of being embedded inline in pod specs

Typical install:

```bash
helm upgrade --install trackone deploy/helm/trackone \
  --set postgres.auth.existingSecret=<your-postgres-secret>
```

If your GHCR images are private, add the published overlay:

```bash
helm upgrade --install trackone deploy/helm/trackone -f deploy/helm/trackone/values-published.yaml
```

The chart now fails fast if you leave the stock `trackone/trackone/trackone`
Postgres credentials in place while using the generated Postgres Secret. For
non-local installs, either:

- set `postgres.auth.existingSecret`
- or override `postgres.auth.database`, `postgres.auth.username`, and `postgres.auth.password`

## Optional legacy local / Minikube override

Use [values-local.yaml](/home/beb/GolandProjects/trackone/deploy/helm/trackone/values-local.yaml) only when you explicitly want local images and build jobs again.

Typical flow:

```bash
scripts/minikube-build-local-images.sh
helm upgrade --install trackone deploy/helm/trackone -f deploy/helm/trackone/values-local.yaml
```

`values-local.yaml` explicitly opts in to the stock local Postgres credentials.

## Generated runtime config

The chart generates and manages these runtime config objects:

- `ConfigMap/trackone-gateway-config` for non-secret gateway config such as `OTS_CALENDARS`
- `Secret/trackone-gateway-env` for sensitive gateway config such as `DATABASE_URL`
- `Secret/postgres-auth` for Postgres bootstrap credentials

The values still live in `values.yaml` and any overlays, but the pods now consume
them via `configMapRef` / `secretKeyRef` instead of inline `env.value` entries.

If you already manage non-secret gateway config elsewhere, set
`gateway.existingConfigMap` and the chart will reuse that ConfigMap instead of
creating `trackone-gateway-config`.

If you already manage sensitive gateway config elsewhere, set
`gateway.existingSecret` and the chart will reuse that Secret instead of
creating `trackone-gateway-env`.

If you already manage Postgres bootstrap credentials elsewhere, set
`postgres.auth.existingSecret` and the chart will reuse that Secret instead of
creating `postgres-auth`.

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
