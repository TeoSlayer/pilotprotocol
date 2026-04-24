# pilot-exporter

Prometheus shim that scrapes the public rendezvous `/api/stats` JSON and re-exports
it as Prometheus metrics for the in-cluster kube-prometheus-stack.

## Apply

```sh
kubectl apply -f k8s/pilot-exporter/deployment.yaml

# Replace the placeholder ConfigMap with the real exporter code:
kubectl -n pilot-integration create configmap pilot-exporter-code \
  --from-file=exporter.py=k8s/pilot-exporter/exporter.py \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n pilot-integration rollout restart deployment/pilot-exporter

kubectl apply -f k8s/pilot-exporter/podmonitor.yaml
kubectl apply -f k8s/pilot-exporter/dashboard.yaml
kubectl apply -f k8s/pilot-exporter/alerts.yaml
```

## Verify

```sh
kubectl -n pilot-integration logs -l app.kubernetes.io/name=pilot-exporter --tail=50
kubectl -n pilot-integration port-forward svc/pilot-exporter 8080:8080
curl -s localhost:8080/metrics | grep ^pilot_
```

## Metrics

| Metric | Type | Notes |
|---|---|---|
| `pilot_total_nodes` | gauge | Registered nodes |
| `pilot_online_nodes` | gauge | Seen within stale threshold |
| `pilot_total_requests` | gauge | Cumulative requests |
| `pilot_req_per_day` | gauge | 24h window |
| `pilot_uptime_seconds` | gauge | Rendezvous process uptime |
| `pilot_probe_up{probe}` | gauge | 1 if probe is currently up |
| `pilot_probe_downtime_seconds_30d{probe}` | gauge | 30d rolling downtime total |
| `pilot_release_latest_info{version,published_at}` | info | Current release banner |
| `pilot_scrape_success` | gauge | 1 if last scrape parsed |
| `pilot_scrape_latency_seconds` | gauge | Last scrape latency |
