# trackone/gateway (local)

This folder contains the Docker build definition for the `trackone/gateway:local` image used by the local Kubernetes overlay.

## Build (for minikube docker driver)

```bash
# Point your docker CLI at minikube's docker daemon
eval "$(minikube -p minikube docker-env)"

# Build the image inside minikube
docker build -t trackone/gateway:local -f docker/gateway/Dockerfile .
```

If you use `imagePullPolicy: Never` (as the overlay does), the image must exist inside the minikube docker daemon.
