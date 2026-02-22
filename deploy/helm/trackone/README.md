# TrackOne Helm chart (local + published modes)

This chart supports two workflows:

## 1) Local / Minikube (build images locally)

- Uses locally built images (e.g. `trackone/gateway:local`) and typically `imagePullPolicy: Never`.
- Suitable for rapid iteration on this repo.

Typical flow:

```bash
scripts/minikube-build-local-images.sh
helm upgrade --install trackone deploy/helm/trackone -f deploy/helm/trackone/values-local.yaml
```

## 2) Published artifacts (no in-cluster Rust builds)

When TrackOne crates + the PyO3 wheel are already published, the Kubernetes workflow should not compile Rust in
Minikube.

- Disable build-check Jobs (`jobs.enabled=false`).
- Deploy `gateway` and `ots-calendar` from a registry image built from *published* artifacts (wheel/crates).

Use the provided template values file and set image repositories/tags:

```bash
helm upgrade --install trackone deploy/helm/trackone -f deploy/helm/trackone/values-published.yaml
```

### Private GHCR images

If your GHCR images are private, create an `imagePullSecret` in the target namespace and reference it via
`imagePullSecrets` in your values file:

```bash
kubectl -n trackone create secret docker-registry ghcr-creds \
  --docker-server=ghcr.io \
  --docker-username=<USER> \
  --docker-password=<TOKEN> \
  --docker-email=<EMAIL>
```
