#!/usr/bin/env python3
"""Pilot release pipeline exporter.

Polls GitHub API for latest release + latest workflow run state, and the
Homebrew tap formula for the version it ships. Exposes Prometheus metrics
on :8080/metrics.

Env:
  GITHUB_REPO              default TeoSlayer/pilot
  HOMEBREW_TAP_REPO        default TeoSlayer/homebrew-pilot
  HOMEBREW_FORMULA_PATH    default Formula/pilot.rb
  POLL_INTERVAL_SECONDS    default 600 (10 min — keeps us under the 60/hr anon quota)
  GITHUB_TOKEN             optional, avoids anon rate limit
"""

from __future__ import annotations

import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Optional

import requests
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Info,
    generate_latest,
    start_http_server,
)

GITHUB_REPO = os.environ.get("GITHUB_REPO", "TeoSlayer/pilot")
HOMEBREW_REPO = os.environ.get("HOMEBREW_TAP_REPO", "TeoSlayer/homebrew-pilot")
HOMEBREW_FORMULA = os.environ.get("HOMEBREW_FORMULA_PATH", "Formula/pilot.rb")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "600"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
PORT = int(os.environ.get("PORT", "8080"))

UA = "pilot-release-exporter/1.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("release-exporter")

registry = CollectorRegistry()

release_age = Gauge(
    "pilot_release_latest_age_seconds",
    "Seconds since the latest GitHub release was published",
    registry=registry,
)
release_info = Info(
    "pilot_release_latest",
    "Latest published GitHub release (tag)",
    registry=registry,
)
release_timestamp = Gauge(
    "pilot_release_latest_published_timestamp_seconds",
    "Unix timestamp when the latest release was published",
    registry=registry,
)

actions_last_status = Gauge(
    "pilot_actions_last_run_success",
    "Whether the most recent run of a workflow succeeded (1) or not (0)",
    ["workflow"],
    registry=registry,
)
actions_last_age = Gauge(
    "pilot_actions_last_run_age_seconds",
    "Seconds since the most recent run of a workflow",
    ["workflow"],
    registry=registry,
)
actions_last_duration = Gauge(
    "pilot_actions_last_run_duration_seconds",
    "Wall-clock duration of the most recent run of a workflow",
    ["workflow"],
    registry=registry,
)

homebrew_version = Info(
    "pilot_homebrew_tap_version",
    "Version string shipped by the Homebrew tap formula",
    registry=registry,
)
homebrew_behind = Gauge(
    "pilot_homebrew_tap_behind_latest",
    "Set to 1 when Homebrew tap formula version != GitHub latest release tag",
    registry=registry,
)

github_rate_remaining = Gauge(
    "pilot_release_exporter_github_rate_remaining",
    "GitHub API rate limit remaining (core)",
    registry=registry,
)
github_rate_limit = Gauge(
    "pilot_release_exporter_github_rate_limit",
    "GitHub API rate limit (core, total)",
    registry=registry,
)

scrape_up = Gauge(
    "pilot_release_exporter_up",
    "Whether the exporter's last poll succeeded (per source)",
    ["source"],
    registry=registry,
)
poll_total = Counter(
    "pilot_release_exporter_polls_total",
    "Number of poll iterations",
    ["source", "outcome"],
    registry=registry,
)


def gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "User-Agent": UA}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def _track_rate(resp: requests.Response) -> None:
    rem = resp.headers.get("X-RateLimit-Remaining")
    lim = resp.headers.get("X-RateLimit-Limit")
    if rem is not None:
        try:
            github_rate_remaining.set(float(rem))
        except ValueError:
            pass
    if lim is not None:
        try:
            github_rate_limit.set(float(lim))
        except ValueError:
            pass


def poll_latest_release() -> Optional[str]:
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    try:
        resp = requests.get(url, headers=gh_headers(), timeout=15)
        _track_rate(resp)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("release poll failed: %s", exc)
        scrape_up.labels(source="release").set(0)
        poll_total.labels(source="release", outcome="error").inc()
        return None

    tag = data.get("tag_name") or "unknown"
    published = data.get("published_at")
    if published:
        try:
            # RFC3339 → epoch
            t = time.strptime(published, "%Y-%m-%dT%H:%M:%SZ")
            ts = time.mktime(t) - time.timezone
            release_timestamp.set(ts)
            release_age.set(max(0.0, time.time() - ts))
        except ValueError:
            log.warning("unparseable published_at: %r", published)

    release_info.info({"tag": tag})
    scrape_up.labels(source="release").set(1)
    poll_total.labels(source="release", outcome="ok").inc()
    return tag


def poll_workflows() -> None:
    url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows"
    try:
        resp = requests.get(url, headers=gh_headers(), timeout=15)
        _track_rate(resp)
        resp.raise_for_status()
        workflows = resp.json().get("workflows", [])
    except Exception as exc:
        log.warning("workflows list failed: %s", exc)
        scrape_up.labels(source="workflows").set(0)
        poll_total.labels(source="workflows", outcome="error").inc()
        return

    # Keep the list short — only observe the high-signal ones plus anything
    # that looks like release.yml. The rest are noise.
    wanted = {"ci.yml", "release.yml", "deploy-website.yml",
              "deploy-rendezvous.yml", "update-homebrew.yml", "codeql.yml"}
    ok = True
    for wf in workflows:
        path = wf.get("path", "").split("/")[-1]
        if path not in wanted:
            continue
        runs_url = (
            f"https://api.github.com/repos/{GITHUB_REPO}"
            f"/actions/workflows/{wf['id']}/runs?per_page=1&status=completed"
        )
        try:
            r = requests.get(runs_url, headers=gh_headers(), timeout=15)
            _track_rate(r)
            r.raise_for_status()
            runs = r.json().get("workflow_runs", [])
        except Exception as exc:
            log.warning("runs poll %s failed: %s", path, exc)
            ok = False
            continue

        if not runs:
            actions_last_status.labels(workflow=path).set(0)
            continue
        run = runs[0]
        conclusion = run.get("conclusion") or ""
        actions_last_status.labels(workflow=path).set(
            1 if conclusion == "success" else 0
        )
        try:
            started = time.mktime(time.strptime(
                run["run_started_at"], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            updated = time.mktime(time.strptime(
                run["updated_at"], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            actions_last_age.labels(workflow=path).set(max(0.0, time.time() - updated))
            actions_last_duration.labels(workflow=path).set(max(0.0, updated - started))
        except (KeyError, ValueError):
            pass

    scrape_up.labels(source="workflows").set(1 if ok else 0)
    poll_total.labels(source="workflows",
                      outcome="ok" if ok else "error").inc()


def poll_homebrew(latest_tag: Optional[str]) -> None:
    url = (
        f"https://raw.githubusercontent.com/{HOMEBREW_REPO}"
        f"/HEAD/{HOMEBREW_FORMULA}"
    )
    try:
        resp = requests.get(url, headers={"User-Agent": UA}, timeout=15)
        resp.raise_for_status()
        body = resp.text
    except Exception as exc:
        log.warning("homebrew poll failed: %s", exc)
        scrape_up.labels(source="homebrew").set(0)
        poll_total.labels(source="homebrew", outcome="error").inc()
        return

    m = re.search(r'version\s+"([^"]+)"', body)
    version = m.group(1) if m else "unknown"
    homebrew_version.info({"version": version})

    if latest_tag:
        # Tags like "v1.8.0" vs Homebrew "1.8.0" — normalize with a leading-v strip
        norm_tap = version.lstrip("v")
        norm_tag = latest_tag.lstrip("v")
        homebrew_behind.set(0 if norm_tap == norm_tag else 1)

    scrape_up.labels(source="homebrew").set(1)
    poll_total.labels(source="homebrew", outcome="ok").inc()


def tick() -> None:
    log.info("polling release/workflows/homebrew")
    tag = poll_latest_release()
    poll_workflows()
    poll_homebrew(tag)


def main() -> None:
    log.info("pilot-release-exporter starting repo=%s poll=%ss token=%s",
             GITHUB_REPO, POLL_INTERVAL, "yes" if GITHUB_TOKEN else "no")
    start_http_server(PORT, registry=registry)
    while True:
        try:
            tick()
        except Exception as exc:
            log.exception("tick failed: %s", exc)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
