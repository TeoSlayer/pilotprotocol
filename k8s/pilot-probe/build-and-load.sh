#!/bin/bash
# Build the pilot-probe image and import it onto every k3s Jetson node.
# Runs locally (assumes docker + ssh access to the Jetson nodes).
set -euo pipefail

IMAGE="${IMAGE:-pilot-probe:latest}"
NODES=(worker-node-2 worker-node-3 worker-node-4 worker-node-10)
SSH_USER="${SSH_USER:-jetson}"

cd "$(dirname "$0")"

echo "==> building $IMAGE (arm64)"
docker buildx build --platform linux/arm64 --load -t "$IMAGE" .

TAR="/tmp/${IMAGE//[:\/]/_}.tar"
echo "==> saving to $TAR"
docker save "$IMAGE" -o "$TAR"

for n in "${NODES[@]}"; do
  echo "==> importing on $n"
  scp -q "$TAR" "$SSH_USER@$n:$TAR"
  ssh "$SSH_USER@$n" "sudo k3s ctr images import '$TAR' && rm -f '$TAR'"
done

rm -f "$TAR"
echo "done."
