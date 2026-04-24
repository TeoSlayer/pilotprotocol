#!/usr/bin/env python3
"""Pilot probe — continuously validates basic pilotctl functionality.

Runs the public pilotctl command surface against each target agent every
PROBE_INTERVAL seconds and exposes per-agent, per-command liveness plus the
relevant scalar metrics (RTT, throughput, setup latency, payload bytes) on
:8080/metrics for Prometheus scraping.

Commands exercised each cycle: find, ping, traceroute, bench, send-message,
send-file, subscribe. Each command contributes an independent
`pilot_probe_reachable{agent,cmd}` gauge so the dashboard can surface which
layer (registry lookup / echo path / data-exchange / event-stream) is
degraded when any one fails.
"""
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.request

from prometheus_client import Counter, Gauge, Info, start_http_server


TARGETS = [s.strip() for s in os.environ.get("PILOT_PROBE_TARGETS", "agent-alpha,agent-beta").split(",") if s.strip()]
INTERVAL = int(os.environ.get("PROBE_INTERVAL_SECONDS", "30"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
BENCH_SIZE_MB = int(os.environ.get("BENCH_SIZE_MB", "1"))
PING_COUNT = int(os.environ.get("PING_COUNT", "3"))
PING_TIMEOUT = os.environ.get("PING_TIMEOUT", "3s")
GITHUB_REPO = os.environ.get("GITHUB_REPO", "TeoSlayer/pilotprotocol")
GITHUB_POLL_SECONDS = int(os.environ.get("GITHUB_POLL_SECONDS", "900"))


reachable = Gauge("pilot_probe_reachable", "1 if agent responded to the named command", ["agent", "cmd"])
cmd_duration = Gauge("pilot_probe_cmd_duration_seconds", "Wall-clock duration of the command invocation", ["agent", "cmd"])
rtt_ms = Gauge("pilot_probe_rtt_ms", "Average ping RTT", ["agent"])
ping_loss_ratio = Gauge("pilot_probe_ping_loss_ratio", "Fraction of pings lost in last cycle", ["agent"])
traceroute_setup_ms = Gauge("pilot_probe_traceroute_setup_ms", "Connection-setup time from traceroute", ["agent"])
traceroute_sample_ms = Gauge("pilot_probe_traceroute_sample_ms", "Median RTT sample from traceroute", ["agent"])
bench_mbps = Gauge("pilot_probe_bench_mbps", "Echo benchmark throughput (total)", ["agent"])
bench_bytes = Gauge("pilot_probe_bench_bytes", "Bytes transferred in last bench", ["agent"])
send_message_bytes = Gauge("pilot_probe_send_message_bytes", "Bytes delivered + ack'd via send-message", ["agent"])
send_file_bytes = Gauge("pilot_probe_send_file_bytes", "Bytes delivered + ack'd via send-file", ["agent"])
peer_count = Gauge("pilot_probe_daemon_peers", "Peers the local daemon knows")
conn_count = Gauge("pilot_probe_daemon_connections", "Open connections on local daemon")
iteration_duration = Gauge("pilot_probe_iteration_duration_seconds", "Seconds spent in the last probe loop")
daemon_up = Gauge("pilot_probe_daemon_up", "1 if local daemon is responsive")
iterations = Counter("pilot_probe_iterations_total", "Total probe loop iterations")
errors = Counter("pilot_probe_errors_total", "Errors per command", ["cmd", "agent"])
daemon_version_info = Info("pilot_probe_daemon_version", "Local pilot-daemon version as reported by pilotctl")
github_version_info = Info("pilot_probe_github_latest_version", "Latest pilotprotocol GitHub release tag")
version_match = Gauge("pilot_probe_version_matches_github", "1 if local daemon version equals latest GitHub release")
version_age_seconds = Gauge("pilot_probe_version_age_seconds", "Seconds since latest GitHub release was published")


CMDS = ["info", "find", "ping", "traceroute", "bench", "send-message", "send-file", "subscribe"]


def run_json(cmd, timeout=15):
    full = ["pilotctl", "--json"] + cmd
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout"
    if p.returncode != 0:
        return None, (p.stderr or p.stdout or "nonzero exit").strip()[:300]
    stdout = (p.stdout or "").strip()
    if not stdout:
        return {}, None
    try:
        return json.loads(stdout), None
    except json.JSONDecodeError as e:
        return None, f"json parse: {e}"


def unwrap(payload):
    """pilotctl returns {status: ok, data: {...}} or {status: error, ...}. Return data dict or None."""
    if not payload:
        return None
    if payload.get("status") == "error":
        return None
    return payload.get("data") or {}


def time_cmd(agent, cmd, args, timeout=15):
    started = time.monotonic()
    data, err = run_json(args, timeout=timeout)
    cmd_duration.labels(agent, cmd).set(time.monotonic() - started)
    if err:
        reachable.labels(agent, cmd).set(0)
        errors.labels(cmd, agent).inc()
        return None
    d = unwrap(data)
    if d is None:
        reachable.labels(agent, cmd).set(0)
        errors.labels(cmd, agent).inc()
        return None
    reachable.labels(agent, cmd).set(1)
    return d


def probe_find(agent):
    d = time_cmd(agent, "find", ["find", agent], timeout=8)
    if d is None:
        return None
    return d.get("address")


def probe_ping(agent):
    d = time_cmd(agent, "ping", ["ping", agent, "--count", str(PING_COUNT), "--timeout", PING_TIMEOUT],
                 timeout=PING_COUNT * 4 + 5)
    if d is None:
        return
    results = d.get("results") or []
    successful = [r for r in results if r.get("rtt_ms") is not None and not r.get("error")]
    if not successful:
        reachable.labels(agent, "ping").set(0)
        errors.labels("ping", agent).inc()
        return
    avg = sum(r["rtt_ms"] for r in successful) / len(successful)
    rtt_ms.labels(agent).set(float(avg))
    ping_loss_ratio.labels(agent).set(1.0 - (len(successful) / max(PING_COUNT, 1)))


def probe_traceroute(agent, address):
    if not address:
        reachable.labels(agent, "traceroute").set(0)
        errors.labels("traceroute", agent).inc()
        return
    d = time_cmd(agent, "traceroute", ["traceroute", address, "--timeout", "10s"], timeout=15)
    if d is None:
        return
    setup = d.get("setup_ms")
    samples = [s.get("rtt_ms") for s in (d.get("rtt_samples") or []) if s.get("rtt_ms") is not None]
    if setup is not None:
        traceroute_setup_ms.labels(agent).set(float(setup))
    if samples:
        samples_sorted = sorted(samples)
        traceroute_sample_ms.labels(agent).set(float(samples_sorted[len(samples_sorted) // 2]))


def probe_bench(agent):
    d = time_cmd(agent, "bench", ["bench", agent, str(BENCH_SIZE_MB), "--timeout", "30s"], timeout=45)
    if d is None:
        return
    mbps = d.get("total_mbps") if d.get("total_mbps") is not None else d.get("send_mbps")
    bytes_recv = d.get("recv_bytes") or 0
    if mbps is None:
        reachable.labels(agent, "bench").set(0)
        errors.labels("bench", agent).inc()
        return
    bench_mbps.labels(agent).set(float(mbps))
    bench_bytes.labels(agent).set(float(bytes_recv))


def probe_send_message(agent):
    payload = f"probe-{int(time.time())}-{agent}"
    d = time_cmd(agent, "send-message",
                 ["send-message", agent, "--data", payload, "--type", "text"],
                 timeout=15)
    if d is None:
        return
    b = d.get("bytes") or 0
    if not b:
        reachable.labels(agent, "send-message").set(0)
        errors.labels("send-message", agent).inc()
        return
    send_message_bytes.labels(agent).set(float(b))


def probe_send_file(agent):
    with tempfile.NamedTemporaryFile("w", suffix=".probe", delete=False) as f:
        f.write(f"probe-payload {int(time.time())} {agent}\n")
        path = f.name
    try:
        d = time_cmd(agent, "send-file", ["send-file", agent, path], timeout=20)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if d is None:
        return
    b = d.get("bytes") or 0
    if not b:
        reachable.labels(agent, "send-file").set(0)
        errors.labels("send-file", agent).inc()
        return
    send_file_bytes.labels(agent).set(float(b))


def probe_subscribe(agent):
    d = time_cmd(agent, "subscribe",
                 ["subscribe", agent, "*", "--count", "1", "--timeout", "2s"],
                 timeout=8)
    # Subscribe returns {events: [...] | null, timeout: true|false}. We only
    # care that the broker responded — timeout:true with status:ok still
    # proves port 1002 is alive. `time_cmd` already set reachable=1 on
    # status:ok payloads.
    if d is None:
        return


def probe_info():
    started = time.monotonic()
    data, err = run_json(["info"], timeout=5)
    cmd_duration.labels("self", "info").set(time.monotonic() - started)
    if err:
        daemon_up.set(0)
        errors.labels("info", "self").inc()
        return
    d = unwrap(data) or data or {}
    daemon_up.set(1)
    peer_count.set(float(d.get("peers", 0) or 0))
    conn_count.set(float(d.get("connections", 0) or 0))
    version = d.get("version") or d.get("daemon_version")
    if version:
        daemon_version_info.info({"version": str(version)})


def probe_version_cli():
    try:
        p = subprocess.run(["pilotctl", "version"], capture_output=True, text=True, timeout=5)
        if p.returncode == 0:
            v = (p.stdout or p.stderr or "").strip().split()[-1]
            if v:
                daemon_version_info.info({"version": v})
                return v
    except Exception:
        pass
    return ""


_last_gh_poll = {"t": 0, "tag": "", "published_epoch": 0}


def refresh_github_latest():
    now = time.time()
    if now - _last_gh_poll["t"] < GITHUB_POLL_SECONDS and _last_gh_poll["tag"]:
        return _last_gh_poll["tag"], _last_gh_poll["published_epoch"]
    url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            d = json.loads(resp.read())
        tag = d.get("tag_name", "") or ""
        pub = d.get("published_at", "") or ""
        epoch = 0
        if pub:
            try:
                epoch = int(time.mktime(time.strptime(pub, "%Y-%m-%dT%H:%M:%SZ")))
            except Exception:
                epoch = 0
        _last_gh_poll.update({"t": now, "tag": tag, "published_epoch": epoch})
        if tag:
            github_version_info.info({"version": tag, "published_at": pub})
        return tag, epoch
    except Exception as exc:
        errors.labels("github", "self").inc()
        print(f"github poll failed: {exc}", flush=True)
        return _last_gh_poll["tag"], _last_gh_poll["published_epoch"]


def probe_agent(agent):
    addr = probe_find(agent)
    probe_ping(agent)
    probe_traceroute(agent, addr)
    probe_bench(agent)
    probe_send_message(agent)
    probe_send_file(agent)
    probe_subscribe(agent)


def probe_iteration():
    started = time.monotonic()
    probe_info()
    for agent in TARGETS:
        try:
            probe_agent(agent)
        except Exception as exc:
            print(f"probe {agent} failed: {exc}", flush=True)

    local_version = probe_version_cli()
    gh_tag, gh_pub_epoch = refresh_github_latest()
    if local_version and gh_tag:
        version_match.set(1.0 if local_version == gh_tag else 0.0)
    if gh_pub_epoch:
        version_age_seconds.set(max(0.0, time.time() - gh_pub_epoch))

    iterations.inc()
    iteration_duration.set(time.monotonic() - started)


def loop():
    while True:
        try:
            probe_iteration()
        except Exception as exc:
            print(f"probe iteration failed: {exc}", flush=True)
        time.sleep(INTERVAL)


def main():
    print(f"pilot-probe starting: targets={TARGETS} interval={INTERVAL}s port={LISTEN_PORT}", flush=True)
    start_http_server(LISTEN_PORT)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    t.join()


if __name__ == "__main__":
    main()
