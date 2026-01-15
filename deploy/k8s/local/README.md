# Local Kubernetes deployment (kustomize)

This folder provides a minimal, *readable* local Kubernetes topology for TrackOne.

- `base/` defines the canonical, environment-agnostic resources.
- `overlays/local/` adds developer conveniences (NodePort, persistent volumes).

## Render the manifest

```bash
cd /home/beb/GolandProjects/trackone
kubectl kustomize deploy/k8s/local/overlays/local > /tmp/trackone-k8s-local.yaml
```

## Apply / delete (local cluster)

```bash
kubectl apply -f /tmp/trackone-k8s-local.yaml
kubectl -n trackone get all

# Cleanup
kubectl delete -f /tmp/trackone-k8s-local.yaml
```

## Components

- **ots-calendar**: stationary OTS calendar sidecar, provides deterministic HTTP readiness (`:8468`).
- **postgres**: local DB for gateway / projections.
- **trackone-gateway**: placeholder deployment with `/health` readiness/liveness.

## Diagrams

See `docs/trackone-k8s-local.puml`.
