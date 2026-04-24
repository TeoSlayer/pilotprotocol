#!/bin/bash
# Build the integration-test image and push it to a local registry
# reachable by the k3s cluster. Assumes the registry is at
# localhost:5000 on the cluster node (standard k3s local-registry
# recipe). Override REGISTRY env var to point elsewhere.
#
# The image bakes:
#   - all Go binaries (rendezvous, daemon, pilotctl, gateway)
#   - the full tests/integration/local/ tree (scripts + helpers +
#     compose files + Dockerfiles)
#   - docker-in-docker entrypoint so the Job pod can run `docker
#     compose up` against its own isolated dockerd.
set -euo pipefail

REGISTRY="${REGISTRY:-localhost:5000}"
IMAGE="${IMAGE:-pilot-integration}"
TAG="${TAG:-latest}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DOCKERFILE="$SCRIPT_DIR/../Dockerfile.runner"

if [ ! -f "$DOCKERFILE" ]; then
    echo "Dockerfile.runner not found at $DOCKERFILE" >&2
    exit 1
fi

echo "[build] repo root:   $REPO_ROOT"
echo "[build] dockerfile:  $DOCKERFILE"
echo "[build] target:      $REGISTRY/$IMAGE:$TAG"

docker build \
    -f "$DOCKERFILE" \
    -t "$REGISTRY/$IMAGE:$TAG" \
    "$REPO_ROOT"

docker push "$REGISTRY/$IMAGE:$TAG"
echo "[build] pushed $REGISTRY/$IMAGE:$TAG"
