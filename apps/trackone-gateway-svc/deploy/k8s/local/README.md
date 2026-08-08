# Local Kubernetes build checks

This Kustomize tree owns build-only Jobs for the reusable Rust packages. It
does not deploy the TrackOne gateway, PostgreSQL, or timestamp services.

Use the Helm chart in `apps/trackone-gateway-svc/deploy/helm/trackone` for the
supported runtime deployment. Keeping one runtime manifest owner prevents
local examples from drifting away from the gateway's authentication, TLS, and
RFC 3161 configuration contract.

Build and load the check images into a local cluster, then render or apply the
overlay:

```bash
kubectl kustomize apps/trackone-gateway-svc/deploy/k8s/local/overlays/local
kubectl apply -k apps/trackone-gateway-svc/deploy/k8s/local/overlays/local
```

The rendered resources are the `trackone` Namespace plus build Jobs for
`trackone-core`, `trackone-constants`, and `trackone-pod-fw`.
