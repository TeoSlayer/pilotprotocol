#!/bin/bash
# Idempotent node_exporter installer for Debian/Ubuntu amd64 GCP VMs.
# Binds to 0.0.0.0:9100 — only reachable via IAP (35.235.240.0/20) when paired with the
# `allow-node-exporter-iap` firewall rule scoped to the `pilot-agent` tag.
set -euo pipefail

VERSION=1.8.2
ARCH=amd64

if systemctl is-active --quiet node_exporter; then
  echo "node_exporter already running, verifying metrics..."
  curl -sf http://localhost:9100/metrics >/dev/null && { echo "OK"; exit 0; }
  echo "active but not serving — reinstalling"
fi

cd /tmp
if [ ! -x /usr/local/bin/node_exporter ]; then
  URL="https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/node_exporter-${VERSION}.linux-${ARCH}.tar.gz"
  if curl -fsSL --connect-timeout 10 "$URL" -o node_exporter.tgz; then
    tar xzf node_exporter.tgz
    sudo mv "node_exporter-${VERSION}.linux-${ARCH}/node_exporter" /usr/local/bin/
    rm -rf "node_exporter-${VERSION}.linux-${ARCH}" node_exporter.tgz
  else
    echo "no egress — expecting tarball already uploaded at /tmp/node_exporter.tgz"
    tar xzf /tmp/node_exporter.tgz
    sudo mv "node_exporter-${VERSION}.linux-${ARCH}/node_exporter" /usr/local/bin/
    rm -rf "node_exporter-${VERSION}.linux-${ARCH}"
  fi
fi

id -u node_exporter >/dev/null 2>&1 || sudo useradd -rs /bin/false node_exporter

sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<'EOF'
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter --web.listen-address=0.0.0.0:9100
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
sleep 2
curl -sf http://localhost:9100/metrics | head -3
echo "DONE: node_exporter installed on $(hostname)"
