#!/usr/bin/env bash
set -euo pipefail

# Build the local images required by deploy/k8s/local/overlays/local
# into the *minikube docker daemon* (docker driver) so imagePullPolicy: Never works.

PROFILE="${MINIKUBE_PROFILE:-minikube}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "Using minikube profile: ${PROFILE}"

# Point docker CLI to minikube's docker daemon.
eval "$(minikube -p "${PROFILE}" docker-env)"

echo "Building trackone/ots-calendar:local"
docker build -t trackone/ots-calendar:local -f docker/calendar/Dockerfile docker/calendar

echo "Building trackone/gateway:local"
docker build -t trackone/gateway:local -f docker/gateway/Dockerfile .

echo "Building trackone/core:local (smoke-test image)"
docker build -t trackone/core:local -f docker/core/Dockerfile .

echo "Building trackone/constants:local (smoke-test image)"
docker build -t trackone/constants:local -f docker/constants/Dockerfile .

echo "Building trackone/pod-fw:local (build-check image)"
docker build -t trackone/pod-fw:local -f docker/pod-fw/Dockerfile .

echo "Done. Images now present in minikube docker daemon:"
# shellcheck disable=SC2196
docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^trackone/(gateway|ots-calendar|core|constants|pod-fw):local$' || true
