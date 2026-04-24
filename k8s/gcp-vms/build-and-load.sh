#!/bin/bash
# Build pilot-iap-scraper (arm64) with bundled gcloud CLI and import to every Jetson node.
set -euo pipefail

IMAGE="${IMAGE:-pilot-iap-scraper:latest}"
BASTION="${BASTION:-jetson@worker-node-2}"
BASTION_PASS="${BASTION_PASS:-jetson}"
AGENT_IPS=(192.168.5.65 192.168.5.61 192.168.5.66)

cd "$(dirname "$0")"

echo "==> building $IMAGE (arm64)"
docker buildx build --platform linux/arm64 --load -t "$IMAGE" .

TAR="/tmp/${IMAGE//[:\/]/_}.tar"
echo "==> saving to $TAR"
docker save "$IMAGE" -o "$TAR"

echo "==> uploading to ${BASTION}"
scp -q "$TAR" "${BASTION}:$TAR"

echo "==> importing on bastion"
ssh "${BASTION}" "echo ${BASTION_PASS} | sudo -S k3s ctr images import $TAR"

for ip in "${AGENT_IPS[@]}"; do
  echo "==> distributing to $ip"
  ssh "${BASTION}" "sshpass -p ${BASTION_PASS} scp -o StrictHostKeyChecking=accept-new $TAR jetson@$ip:$TAR && \
                    sshpass -p ${BASTION_PASS} ssh -o StrictHostKeyChecking=accept-new jetson@$ip 'echo ${BASTION_PASS} | sudo -S k3s ctr images import $TAR && rm -f $TAR'"
done

ssh "${BASTION}" "rm -f $TAR"
rm -f "$TAR"
echo "done."
