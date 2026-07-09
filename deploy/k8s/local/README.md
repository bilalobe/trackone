# TrackOne local Kubernetes deployment

This folder contains a **local/dev** Kubernetes setup (kustomize base + overlay).

## What gets deployed
The `deploy/k8s/local/overlays/local` overlay deploys only these workloads:

- `ots-calendar` (Deployment)
- `trackone-gateway` (Deployment)
- `postgres` (StatefulSet)
- Rust build-only checks for `trackone-core`, `trackone-constants`, and
  `trackone-pod-fw` (Jobs)

You can verify the rendered resources with:

```bash
kubectl kustomize deploy/k8s/local/overlays/local | grep -E '^kind:'
```

## What the "other crates" are
The other Rust workspace crates (`trackone-core`, `trackone-constants`, `trackone-pod-fw`) are **libraries / firmware**, not long-running services.

They do have Dockerfiles (build-only images) so you can build them reproducibly
and load them into Minikube, but they are **not** deployed as `Deployment`s by
default.

Images:

- `trackone/core:local`
- `trackone/constants:local`
- `trackone/pod-fw:local`

Build the Rust build-only images into Minikube's Docker daemon (docker driver)
with:

```bash
eval "$(minikube -p ${MINIKUBE_PROFILE:-minikube} docker-env)"
docker build -t trackone/core:local -f deploy/docker/core/Dockerfile .
docker build -t trackone/constants:local -f deploy/docker/constants/Dockerfile .
docker build -t trackone/pod-fw:local -f deploy/docker/pod-fw/Dockerfile .
```

The `trackone-gateway` and `ots-calendar` workloads are placeholders in this
local Kustomize tree. Point those images at a registry artifact or provide local
images before applying the overlay.

Run one to sanity-check it:

```bash
eval "$(minikube -p ${MINIKUBE_PROFILE:-minikube} docker-env)"
docker run --rm trackone/core:local
docker run --rm trackone/pod-fw:local
```

The pod firmware image defaults to a release-mode production build with default
features disabled. That keeps the local image, Kustomize Job, and Helm Job
aligned with the firmware feature policy in `trackone-pod-fw`.
