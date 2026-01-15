# TrackOne local Kubernetes deployment

This folder contains a **local/dev** Kubernetes setup (kustomize base + overlay).

## What gets deployed
The `deploy/k8s/local/overlays/local` overlay deploys only these workloads:

- `ots-calendar` (Deployment)
- `trackone-gateway` (Deployment)
- `postgres` (StatefulSet)

You can verify the rendered resources with:

```bash
kubectl kustomize deploy/k8s/local/overlays/local | grep -E '^kind:'
```

## What the "other crates" are
The other Rust workspace crates (`trackone-core`, `trackone-constants`, `trackone-pod-fw`) are **libraries / firmware**, not long-running services.

They do have Dockerfiles (build-only images) so you can build them reproducibly and load them into Minikube, but they are **not** deployed as `Deployment`s by default.

Images:

- `trackone/core:local`
- `trackone/constants:local`
- `trackone/pod-fw:local`

Build them into Minikube (docker driver) with:

```bash
scripts/minikube-build-local-images.sh
```

Run one to sanity-check it:

```bash
eval "$(minikube -p minikube docker-env)"
docker run --rm trackone/core:local
```
