#!/usr/bin/env python3
"""Pilot Protocol stats → Prometheus metrics shim.

Polls the rendezvous /api/stats JSON every SCRAPE_INTERVAL seconds and
re-exports a focused subset as Prometheus metrics on :8080/metrics.
"""
import os
import time
import threading
import urllib.request
import json
from prometheus_client import start_http_server, Gauge, Counter, Info

SOURCE_URL = os.environ.get("PILOT_STATS_URL", "http://34.71.57.205:3000/api/stats")
SCRAPE_INTERVAL = int(os.environ.get("SCRAPE_INTERVAL_SECONDS", "15"))
SCRAPE_TIMEOUT = int(os.environ.get("SCRAPE_TIMEOUT_SECONDS", "5"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

total_nodes = Gauge("pilot_total_nodes", "Total registered nodes in the registry")
online_nodes = Gauge("pilot_online_nodes", "Nodes seen within the stale threshold")

total_requests = Gauge("pilot_total_requests", "Cumulative registry requests (resets on rendezvous restart)")
req_per_day = Gauge("pilot_req_per_day", "Requests over the last 24h")
uptime_seconds = Gauge("pilot_uptime_seconds", "Rendezvous process uptime")

probe_up = Gauge("pilot_probe_up", "1 if probe is currently up, 0 if down", ["probe"])
probe_last_success = Gauge(
    "pilot_probe_last_success_timestamp_seconds",
    "Unix timestamp of last successful probe",
    ["probe"],
)
probe_staleness = Gauge(
    "pilot_probe_staleness_seconds",
    "Seconds since last successful probe",
    ["probe"],
)
probe_downtime_30d = Gauge(
    "pilot_probe_downtime_seconds_30d",
    "Sum of downtime intervals in the last 30 days",
    ["probe"],
)
probe_downtime_events_30d = Gauge(
    "pilot_probe_downtime_events_30d",
    "Count of recorded downtime intervals in the last 30 days",
    ["probe"],
)
probe_availability_30d = Gauge(
    "pilot_probe_availability_30d_ratio",
    "30-day availability ratio (1 - downtime/window)",
    ["probe"],
)

restarts_recorded = Gauge(
    "pilot_rendezvous_restart_events",
    "Number of rendezvous restart events tracked in the snapshot",
)
last_restart_seconds = Gauge(
    "pilot_rendezvous_last_restart_timestamp_seconds",
    "Unix timestamp of the most recent rendezvous restart",
)
time_since_last_restart = Gauge(
    "pilot_rendezvous_time_since_last_restart_seconds",
    "Seconds since the most recent rendezvous restart",
)

release_info = Info("pilot_release_latest", "Latest published release banner")
scrape_ok = Gauge("pilot_scrape_success", "1 if the last scrape parsed, 0 otherwise")
scrape_latency = Gauge("pilot_scrape_latency_seconds", "Latency of the last scrape")
scrape_count = Counter("pilot_scrape_attempts_total", "Total scrape attempts", ["outcome"])

THIRTY_DAYS_S = 30 * 86400


def fetch_once() -> None:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(SOURCE_URL, timeout=SCRAPE_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001 — log + retry next tick
        scrape_ok.set(0)
        scrape_count.labels(outcome="error").inc()
        print(f"scrape failed: {exc}", flush=True)
        return

    now = time.time()

    total_nodes.set(data.get("total_nodes", 0) or 0)
    online_nodes.set(data.get("active_nodes", 0) or 0)

    total_requests.set(data.get("total_requests", 0) or 0)
    req_per_day.set(data.get("req_per_day", 0) or 0)
    uptime_seconds.set(data.get("uptime_secs", 0) or 0)

    probes = data.get("probes") or {}
    for name, ps in probes.items():
        ps = ps or {}
        up = 0 if (ps.get("current_down_start", 0) or 0) > 0 else 1
        probe_up.labels(probe=name).set(up)

        last_ms = ps.get("last_success", 0) or 0
        last_s = last_ms / 1000.0 if last_ms else 0
        probe_last_success.labels(probe=name).set(last_s)
        probe_staleness.labels(probe=name).set(max(0.0, now - last_s) if last_s else 0)

        intervals = ps.get("downtime_intervals") or []
        down_ms = sum((iv[1] - iv[0]) for iv in intervals if len(iv) >= 2)
        down_s = down_ms / 1000.0
        probe_downtime_30d.labels(probe=name).set(down_s)
        probe_downtime_events_30d.labels(probe=name).set(len(intervals))
        avail = 1.0 - (down_s / THIRTY_DAYS_S) if THIRTY_DAYS_S > 0 else 0.0
        probe_availability_30d.labels(probe=name).set(max(0.0, min(1.0, avail)))

    restarts = data.get("restart_events") or []
    restarts_recorded.set(len(restarts))
    if restarts:
        last_restart_ms = max(restarts)
        last_s = last_restart_ms / 1000.0
        last_restart_seconds.set(last_s)
        time_since_last_restart.set(max(0.0, now - last_s))
    else:
        last_restart_seconds.set(0)
        time_since_last_restart.set(0)

    banner = data.get("release_banner") or {}
    release_info.info(
        {
            "version": str(banner.get("version", "")),
            "published_at": str(banner.get("published_at", "")),
        }
    )

    scrape_ok.set(1)
    scrape_count.labels(outcome="ok").inc()
    scrape_latency.set(time.monotonic() - started)


def scrape_loop() -> None:
    while True:
        fetch_once()
        time.sleep(SCRAPE_INTERVAL)


def main() -> None:
    print(
        f"pilot-exporter starting: url={SOURCE_URL} interval={SCRAPE_INTERVAL}s port={LISTEN_PORT}",
        flush=True,
    )
    start_http_server(LISTEN_PORT)
    t = threading.Thread(target=scrape_loop, daemon=True)
    t.start()
    t.join()


if __name__ == "__main__":
    main()
