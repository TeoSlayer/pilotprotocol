#!/bin/bash
# Populate the shared preloaded-tarballs PVC with the contents of
# tests/integration/k8s/preloaded/ (~383 MB of Docker base-image tars).
#
# Strategy: launch a short-lived `seeder` pod with the RWX PVC mounted,
# `kubectl cp` each tarball into it, then delete the pod. Idempotent —
# only copies tars whose size differs from what's already on the PVC.
#
# Prerequisites:
#   - The PVC exists (run `helm install integration ./helm/integration-tests`
#     once to create it; `helm.sh/resource-policy: keep` preserves it).
#   - kubectl points at the target cluster.
#
# Usage:
#   bash tests/integration/k8s/scripts/seed-preloaded.sh
#
# Env overrides:
#   NAMESPACE   (default: default)
#   PVC_NAME    (default: pilot-preloaded-tarballs)
#   POD_NAME    (default: preloaded-seeder)
#   POD_IMAGE   (default: busybox:1.37)

set -euo pipefail

NAMESPACE="${NAMESPACE:-default}"
PVC_NAME="${PVC_NAME:-pilot-preloaded-tarballs}"
POD_NAME="${POD_NAME:-preloaded-seeder}"
POD_IMAGE="${POD_IMAGE:-busybox:1.37}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PRELOADED_DIR="$(cd "$SCRIPT_DIR/../preloaded" && pwd)"

if [ ! -d "$PRELOADED_DIR" ]; then
    echo "[seed] preloaded dir not found: $PRELOADED_DIR" >&2
    exit 1
fi

TARS=("$PRELOADED_DIR"/*.tar)
if [ ! -f "${TARS[0]}" ]; then
    echo "[seed] no *.tar files under $PRELOADED_DIR — nothing to seed" >&2
    exit 1
fi

echo "[seed] namespace=$NAMESPACE pvc=$PVC_NAME pod=$POD_NAME"
echo "[seed] source:   $PRELOADED_DIR"
echo "[seed] tarballs: ${#TARS[@]} file(s)"

# Sanity: PVC must exist.
if ! kubectl -n "$NAMESPACE" get pvc "$PVC_NAME" >/dev/null 2>&1; then
    echo "[seed] PVC $NAMESPACE/$PVC_NAME does not exist. Install the chart first:" >&2
    echo "[seed]   helm install integration ./tests/integration/k8s/helm/integration-tests" >&2
    exit 1
fi

# Clean up any leftover seeder pod from a previous run.
kubectl -n "$NAMESPACE" delete pod "$POD_NAME" --ignore-not-found --wait=true >/dev/null

cat <<EOF | kubectl -n "$NAMESPACE" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  labels:
    pilot-integration/role: preloaded-seeder
spec:
  restartPolicy: Never
  containers:
    - name: seeder
      image: $POD_IMAGE
      command: ["sh", "-c", "mkdir -p /preloaded && sleep 3600"]
      volumeMounts:
        - name: preloaded
          mountPath: /preloaded
  volumes:
    - name: preloaded
      persistentVolumeClaim:
        claimName: $PVC_NAME
EOF

echo "[seed] waiting for seeder pod to be Ready..."
kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD_NAME" --timeout=180s >/dev/null

copied=0
skipped=0
for tar in "${TARS[@]}"; do
    base="$(basename "$tar")"
    local_size="$(stat -f %z "$tar" 2>/dev/null || stat -c %s "$tar")"
    remote_size="$(kubectl -n "$NAMESPACE" exec "$POD_NAME" -- sh -c "stat -c %s /preloaded/$base 2>/dev/null || echo 0" | tr -d '\r')"
    if [ "$local_size" = "$remote_size" ]; then
        echo "[seed] skip $base (same size: $local_size bytes)"
        skipped=$((skipped+1))
        continue
    fi
    echo "[seed] copy $base ($local_size bytes)"
    kubectl -n "$NAMESPACE" cp "$tar" "$POD_NAME:/preloaded/$base"
    copied=$((copied+1))
done

echo "[seed] done: copied=$copied skipped=$skipped"

kubectl -n "$NAMESPACE" delete pod "$POD_NAME" --wait=true >/dev/null
echo "[seed] seeder pod removed"
