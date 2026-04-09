"""
Pilot Protocol Service Agent Dashboard.

Polls pilotctl commands on a schedule, tracks health/output/latency,
and serves a real-time web dashboard.

Usage:
    ./start.sh
    python -m uvicorn server:app --host 0.0.0.0 --port 7700 --reload
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import shutil
import subprocess
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

log = logging.getLogger("dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONFIG_PATH = Path(__file__).parent / "config.yaml"
INBOX_DIR = Path.home() / ".pilot" / "inbox"

# Resolve pilotctl binary — prefer explicit env, then ~/.pilot/bin, then PATH.
def _find_pilotctl() -> str:
    if env := os.environ.get("PILOTCTL"):
        return env
    home_bin = Path.home() / ".pilot" / "bin" / "pilotctl"
    if home_bin.is_file() and os.access(home_bin, os.X_OK):
        return str(home_bin)
    found = shutil.which("pilotctl")
    if found:
        return found
    return str(home_bin)  # fallback — let the error surface later

PILOTCTL = _find_pilotctl()

# Thread pool for blocking subprocess calls (avoids asyncio pipe + SIGKILL on macOS).
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def _load_config() -> list[dict]:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)["agents"]


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class AgentState:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.id: str = cfg["id"]
        self.status: str = "pending"   # pending | polling | ok | error | timeout
        self.last_poll: str | None = None
        self.last_response_time: float | None = None
        self.last_output: str | None = None
        self.last_error: str | None = None
        self.poll_count: int = 0
        self.error_count: int = 0
        self.history: deque = deque(maxlen=10)
        self._running: bool = False

    def _full_command(self) -> str:
        """Build the exact pilotctl command string shown in the dashboard."""
        t = self.cfg.get("type", "")
        node = self.cfg.get("node", "")
        body = self.cfg.get("body", "")
        if t == "ai":
            return f'pilotctl ai "{body}" --node {node}'
        elif t == "clawdit":
            return f'pilotctl clawdit "{body}" --node {node}'
        elif t == "scriptorium":
            cmd = self.cfg.get("command", "")
            return f'pilotctl scriptorium {cmd} "{body}" --node {node}'
        return f"pilotctl {t} {body}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.cfg["name"],
            "description": self.cfg.get("description", ""),
            "node": self.cfg.get("node", ""),
            "type": self.cfg.get("type", ""),
            "command": self.cfg.get("command", ""),
            "body": self.cfg.get("body", ""),
            "full_command": self._full_command(),
            "poll_interval": self.cfg.get("poll_interval", 120),
            "timeout": self.cfg.get("timeout", 120),
            "status": self.status,
            "last_poll": self.last_poll,
            "last_response_time": self.last_response_time,
            "last_output": self.last_output,
            "last_error": self.last_error,
            "poll_count": self.poll_count,
            "error_count": self.error_count,
            "success_rate": (
                round((self.poll_count - self.error_count) / self.poll_count * 100, 1)
                if self.poll_count else None
            ),
            "history": list(self.history),
        }


_agents: dict[str, AgentState] = {}


def _init_agents():
    for cfg in _load_config():
        _agents[cfg["id"]] = AgentState(cfg)


# ---------------------------------------------------------------------------
# Subprocess execution — uses blocking subprocess.run in a thread pool
# to avoid macOS asyncio pipe + SIGKILL issues.
# ---------------------------------------------------------------------------

def _blocking_run(cmd: list[str], timeout: float) -> tuple[str, str, int]:
    """Run a command in a blocking subprocess. Returns (stdout, stderr, returncode)."""
    log.info("exec: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"command timed out after {timeout:.0f}s")


async def _run_cmd(cmd: list[str], timeout: float) -> str:
    """Run cmd in thread pool, return stdout. Raises on non-zero exit."""
    loop = asyncio.get_event_loop()
    out, err, rc = await loop.run_in_executor(
        _executor, _blocking_run, cmd, timeout,
    )
    if rc != 0:
        detail = err or out or f"exit code {rc}"
        log.warning("command failed (rc=%d): %s — %s", rc, " ".join(cmd), detail)
        raise RuntimeError(detail)
    log.info("ok (%d bytes)", len(out))
    return out or err


# ---------------------------------------------------------------------------
# Command runners
# ---------------------------------------------------------------------------

async def _run_ai(state: AgentState) -> tuple[str, float]:
    cfg = state.cfg
    cmd = [PILOTCTL, "ai", cfg["body"], "--node", cfg["node"]]
    start = time.monotonic()
    out = await _run_cmd(cmd, cfg.get("timeout", 120))
    return out, time.monotonic() - start


async def _run_clawdit(state: AgentState) -> tuple[str, float]:
    cfg = state.cfg
    cmd = [PILOTCTL, "clawdit", cfg["body"], "--node", cfg["node"]]
    start = time.monotonic()
    out = await _run_cmd(cmd, cfg.get("timeout", 120))
    return out, time.monotonic() - start


async def _run_scriptorium(state: AgentState) -> tuple[str, float]:
    """Send via scriptorium, then poll ~/.pilot/inbox/ for the reply."""
    cfg = state.cfg
    node = cfg["node"]
    timeout = cfg.get("timeout", 90)

    # Resolve dynamic body: replace {yesterday} with yesterday's date.
    body = cfg.get("body", "")
    if "{yesterday}" in body:
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT00:00:00Z")
        body = body.replace("{yesterday}", yesterday)
    if "{yesterday_date}" in body:
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        body = body.replace("{yesterday_date}", yesterday)

    # Snapshot inbox before sending
    seen: set[str] = set()
    if INBOX_DIR.exists():
        seen = {f.name for f in INBOX_DIR.iterdir() if f.suffix == ".json"}

    start = time.monotonic()

    # Send via scriptorium (blocks in thread pool)
    cmd = [PILOTCTL, "scriptorium", cfg["command"], body, "--node", node]
    out = await _run_cmd(cmd, 30)  # ACK should come fast

    # Poll inbox for reply (blocking loop in thread pool)
    loop = asyncio.get_event_loop()
    reply = await loop.run_in_executor(
        _executor, _poll_inbox_sync, node, seen, timeout - 30,
    )
    return str(reply)[:2000], time.monotonic() - start


def _poll_inbox_sync(node: str, seen: set[str], timeout: float) -> str:
    """Blocking inbox poll — runs in thread pool."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(3)
        if not INBOX_DIR.exists():
            continue
        for f in INBOX_DIR.iterdir():
            if f.name in seen or f.suffix != ".json":
                continue
            seen.add(f.name)
            try:
                msg = json.loads(f.read_text())
            except Exception:
                continue
            if msg.get("from") != node:
                continue
            raw = msg.get("data", "")
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, str) else json.dumps(parsed, indent=2)
            except Exception:
                return raw
    raise TimeoutError(f"no reply from {node} within {timeout:.0f}s")


_RUNNERS = {
    "ai": _run_ai,
    "clawdit": _run_clawdit,
    "scriptorium": _run_scriptorium,
}


# ---------------------------------------------------------------------------
# Poll one agent
# ---------------------------------------------------------------------------

async def poll_agent(state: AgentState) -> None:
    if state._running:
        return
    state._running = True
    state.status = "polling"

    runner = _RUNNERS.get(state.cfg.get("type", ""))
    if runner is None:
        state.status = "error"
        state.last_error = f"unknown agent type: {state.cfg.get('type')}"
        state._running = False
        return

    try:
        output, elapsed = await runner(state)
        state.status = "ok"
        state.last_output = output
        state.last_error = None
        state.last_response_time = round(elapsed, 2)
    except TimeoutError as e:
        state.status = "timeout"
        state.last_error = str(e)
        state.last_output = None
        state.last_response_time = state.cfg.get("timeout")
        state.error_count += 1
    except Exception as e:
        state.status = "error"
        state.last_error = str(e)
        state.last_output = None
        state.last_response_time = None
        state.error_count += 1

    state.last_poll = datetime.now(timezone.utc).isoformat()
    state.poll_count += 1
    state.history.appendleft({
        "time": state.last_poll,
        "status": state.status,
        "response_time": state.last_response_time,
        "output": (state.last_output or state.last_error or "")[:300],
    })
    state._running = False


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------

async def _poll_loop() -> None:
    while True:
        now = time.time()
        for state in list(_agents.values()):
            if state._running:
                continue
            interval = state.cfg.get("poll_interval", 120)
            last_ts = (
                datetime.fromisoformat(state.last_poll).timestamp()
                if state.last_poll else 0
            )
            if (now - last_ts) >= interval:
                asyncio.create_task(poll_agent(state))
        await asyncio.sleep(10)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="Service Agent Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    log.info("pilotctl binary: %s", PILOTCTL)
    log.info("inbox dir: %s", INBOX_DIR)
    _init_agents()
    log.info("loaded %d agents: %s", len(_agents), ", ".join(_agents.keys()))
    asyncio.create_task(_poll_loop())


@app.get("/api/status")
async def get_status():
    return JSONResponse({aid: s.to_dict() for aid, s in _agents.items()})


@app.post("/api/poll/{agent_id}")
async def trigger_poll(agent_id: str):
    state = _agents.get(agent_id)
    if state is None:
        return JSONResponse({"error": "unknown agent"}, status_code=404)
    if state._running:
        return JSONResponse({"status": "already polling"})
    asyncio.create_task(poll_agent(state))
    return JSONResponse({"status": "triggered"})


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return _HTML


# ---------------------------------------------------------------------------
# Dashboard HTML (embedded)
# ---------------------------------------------------------------------------

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pilot Protocol — Service Agent Monitor</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #0d0f14;
    --surface: #141720;
    --border: #1e2330;
    --text: #cdd6f4;
    --muted: #6c7086;
    --green: #a6e3a1;
    --red: #f38ba8;
    --yellow: #f9e2af;
    --blue: #89b4fa;
    --purple: #cba6f7;
    --teal: #94e2d5;
    --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  }

  body {
    font-family: var(--mono);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 24px;
  }

  /* ── Header ── */
  header {
    display: flex;
    align-items: baseline;
    gap: 16px;
    margin-bottom: 32px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 16px;
  }
  header h1 { font-size: 1.1rem; font-weight: 600; color: var(--blue); letter-spacing: 0.04em; }
  header .subtitle { font-size: 0.75rem; color: var(--muted); }
  .refresh-info { margin-left: auto; font-size: 0.7rem; color: var(--muted); }

  /* ── Summary bar ── */
  .summary {
    display: flex;
    gap: 24px;
    margin-bottom: 28px;
    font-size: 0.75rem;
  }
  .summary-item { display: flex; align-items: center; gap: 6px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
  .dot-ok      { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .dot-error   { background: var(--red); box-shadow: 0 0 6px var(--red); }
  .dot-timeout { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
  .dot-polling { background: var(--blue); animation: pulse 1.2s infinite; }
  .dot-pending { background: var(--muted); }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  /* ── Grid ── */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(480px, 1fr));
    gap: 16px;
    margin-bottom: 48px;
  }

  /* ── Agent card ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    transition: border-color 0.2s;
  }
  .card.status-ok      { border-left: 3px solid var(--green); }
  .card.status-error   { border-left: 3px solid var(--red); }
  .card.status-timeout { border-left: 3px solid var(--yellow); }
  .card.status-polling { border-left: 3px solid var(--blue); }
  .card.status-pending { border-left: 3px solid var(--muted); }

  .card-header {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    margin-bottom: 14px;
  }
  .card-status-dot { margin-top: 4px; flex-shrink: 0; }
  .card-title { font-size: 0.9rem; font-weight: 600; color: var(--text); }
  .card-desc  { font-size: 0.7rem; color: var(--muted); margin-top: 2px; }
  .card-node  { font-size: 0.68rem; color: var(--purple); margin-top: 3px; }
  .poll-btn {
    margin-left: auto;
    background: none;
    border: 1px solid var(--border);
    color: var(--muted);
    border-radius: 4px;
    padding: 4px 10px;
    font-family: var(--mono);
    font-size: 0.68rem;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.15s;
    flex-shrink: 0;
  }
  .poll-btn:hover { border-color: var(--blue); color: var(--blue); }
  .poll-btn:disabled { opacity: 0.4; cursor: not-allowed; }

  /* ── Stats row ── */
  .stats {
    display: flex;
    gap: 20px;
    margin-bottom: 14px;
    font-size: 0.7rem;
    color: var(--muted);
  }
  .stat-val { color: var(--text); font-weight: 500; }
  .stat-ok      .stat-val { color: var(--green); }
  .stat-error   .stat-val { color: var(--red); }
  .stat-timeout .stat-val { color: var(--yellow); }

  /* ── Command box ── */
  .cmd-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 12px;
    font-size: 0.68rem;
    line-height: 1.5;
    color: var(--teal);
    white-space: nowrap;
    overflow-x: auto;
    margin-bottom: 8px;
    opacity: 0.85;
  }

  /* ── Output box ── */
  .output-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px 12px;
    font-size: 0.72rem;
    line-height: 1.6;
    color: var(--text);
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 140px;
    overflow-y: auto;
    margin-bottom: 12px;
  }
  .output-box.error   { color: var(--red); }
  .output-box.timeout { color: var(--yellow); }
  .output-box.polling { color: var(--blue); animation: pulse 1.2s infinite; }
  .output-box.pending { color: var(--muted); }

  /* ── History strip ── */
  .history-label { font-size: 0.65rem; color: var(--muted); margin-bottom: 4px; }
  .history-strip { display: flex; gap: 3px; }
  .history-pip {
    width: 12px; height: 12px; border-radius: 2px; flex-shrink: 0;
    title: attr(data-tip);
    cursor: default;
  }
  .history-pip.ok      { background: var(--green); opacity: 0.85; }
  .history-pip.error   { background: var(--red); opacity: 0.85; }
  .history-pip.timeout { background: var(--yellow); opacity: 0.85; }
  .history-pip.polling { background: var(--blue); opacity: 0.5; }
  .history-pip.empty   { background: var(--border); }

  /* ── Template section ── */
  .template-section {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    background: var(--surface);
  }
  .template-section h2 {
    font-size: 0.85rem;
    color: var(--teal);
    margin-bottom: 16px;
    letter-spacing: 0.05em;
  }
  .template-section h3 {
    font-size: 0.75rem;
    color: var(--blue);
    margin: 16px 0 8px;
    letter-spacing: 0.03em;
  }
  .template-section p, .template-section li {
    font-size: 0.72rem;
    color: var(--muted);
    line-height: 1.7;
    margin-bottom: 6px;
  }
  .template-section li { margin-left: 16px; }
  pre.code-block {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 12px;
    font-size: 0.7rem;
    color: var(--text);
    overflow-x: auto;
    margin: 8px 0 14px;
    white-space: pre;
  }
  .kw  { color: var(--purple); }
  .str { color: var(--green); }
  .cmt { color: var(--muted); }
</style>
</head>
<body>

<header>
  <h1>⬡ Pilot Protocol — Service Agent Monitor</h1>
  <span class="subtitle">overlay network · service agents · live status</span>
  <span class="refresh-info" id="refresh-info">refreshing every 5s</span>
</header>

<div class="summary" id="summary"></div>

<div class="grid" id="grid"></div>

<div class="template-section">
  <h2>// HOW TO MAKE YOUR COMMAND VISIBLE AND POLLED BY THE DASHBOARD</h2>

  <h3>Step 1 — Create a service agent from the template</h3>
  <pre class="code-block"><span class="cmt"># Copy the template</span>
cp -r service-agents/_template my-agent
cd my-agent

<span class="cmt"># Edit: agent name, system prompt, tools</span>
vi agent/prompts.py
vi agent/tools.py</pre>

  <h3>Step 2 — Register the endpoint on the remote node</h3>
  <p>Add your agent to <code>~/.pilot/endpoints.yaml</code> on the node where it runs:</p>
  <pre class="code-block"><span class="kw">commands:</span>
  <span class="kw">- name:</span> <span class="str">my-agent</span>
    <span class="kw">link:</span> <span class="str">http://localhost:8400/chat</span>
    <span class="kw">arg_regex:</span> <span class="str">'^(?P&lt;message&gt;.+)$'</span></pre>

  <h3>Step 3 — Add an entry to dashboard/config.yaml</h3>
  <pre class="code-block"><span class="kw">agents:</span>
  <span class="kw">- id:</span>          <span class="str">my-agent</span>
    <span class="kw">name:</span>        <span class="str">"My Agent"</span>
    <span class="kw">description:</span> <span class="str">"What this agent does"</span>
    <span class="kw">node:</span>        <span class="str">"0:0000.0000.XXXX"</span>  <span class="cmt"># remote node address</span>
    <span class="kw">type:</span>        <span class="str">scriptorium</span>          <span class="cmt"># or: ai | clawdit</span>
    <span class="kw">command:</span>     <span class="str">my-agent</span>             <span class="cmt"># matches endpoints.yaml name</span>
    <span class="kw">body:</span>        <span class="str">"status check"</span>
    <span class="kw">poll_interval:</span> <span class="str">120</span>
    <span class="kw">timeout:</span>     <span class="str">90</span></pre>

  <h3>Step 4 — Add a built-in CLI command (optional)</h3>
  <p>For agents you want reachable as <code>pilotctl myagent "query"</code>, add a case in
  <code>cmd/pilotctl/main.go</code> following the pattern of <code>cmdAi</code> / <code>cmdClawdit</code>,
  then set <code>type: myagent</code> in config.yaml and add a runner function in <code>server.py</code>.</p>

  <h3>Step 5 — Restart the dashboard</h3>
  <pre class="code-block">cd service-agents/dashboard && ./start.sh</pre>
</div>

<script>
const STATUS_LABELS = { ok:'ok', error:'error', timeout:'timeout', polling:'polling...', pending:'pending' };
const STATUS_COLOR  = { ok:'var(--green)', error:'var(--red)', timeout:'var(--yellow)', polling:'var(--blue)', pending:'var(--muted)' };

let _data = {};

function fmt_time(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

function fmt_elapsed(s) {
  if (s == null) return '—';
  return s >= 1 ? s.toFixed(1) + 's' : (s * 1000).toFixed(0) + 'ms';
}

function truncate(s, n=200) {
  if (!s) return '';
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function render_summary(agents) {
  const counts = { ok:0, error:0, timeout:0, polling:0, pending:0 };
  for (const a of Object.values(agents)) counts[a.status] = (counts[a.status]||0) + 1;
  const el = document.getElementById('summary');
  el.innerHTML = Object.entries(counts).filter(([,n])=>n>0).map(([s,n])=>`
    <span class="summary-item">
      <span class="dot dot-${s}"></span>
      <span>${n} ${STATUS_LABELS[s]||s}</span>
    </span>`).join('');
}

function render_card(a) {
  const statusClass = `status-${a.status}`;
  const dotClass    = `dot dot-${a.status}`;
  const outClass    = a.status === 'ok' ? '' : (a.status==='polling'?'polling':'error');
  const outText     = a.status === 'polling' ? '⏳ polling…'
    : a.last_output  ? truncate(a.last_output)
    : a.last_error   ? '✗ ' + truncate(a.last_error)
    : '—';
  const pips = (a.history.length ? a.history : Array(5).fill(null)).slice(0,10).map(h =>
    h ? `<span class="history-pip ${h.status}" title="${fmt_time(h.time)} · ${fmt_elapsed(h.response_time)}"></span>`
      : `<span class="history-pip empty"></span>`
  ).join('');

  const successRate = a.success_rate != null ? a.success_rate + '%' : '—';
  return `
  <div class="card ${statusClass}" id="card-${a.id}">
    <div class="card-header">
      <span class="card-status-dot"><span class="${dotClass}"></span></span>
      <div>
        <div class="card-title">${a.name}</div>
        <div class="card-desc">${a.description}</div>
        <div class="card-node">${a.node}</div>
      </div>
      <button class="poll-btn" onclick="triggerPoll('${a.id}')" id="btn-${a.id}"
        ${a.status==='polling'?'disabled':''}>▶ poll now</button>
    </div>

    <div class="stats">
      <span>last poll <span class="stat-val">${fmt_time(a.last_poll)}</span></span>
      <span class="stat-${a.status}">response <span class="stat-val">${fmt_elapsed(a.last_response_time)}</span></span>
      <span>success <span class="stat-val">${successRate}</span></span>
      <span>polls <span class="stat-val">${a.poll_count}</span></span>
      <span>errors <span class="stat-val">${a.error_count}</span></span>
    </div>

    <div class="cmd-box">$ ${a.full_command || ''}</div>

    <div class="output-box ${outClass}">${outText}</div>

    <div class="history-label">recent polls ↓</div>
    <div class="history-strip">${pips}</div>
  </div>`;
}

function render(data) {
  _data = data;
  render_summary(data);
  const grid = document.getElementById('grid');
  grid.innerHTML = Object.values(data).map(render_card).join('');
}

async function refresh() {
  try {
    const r = await fetch('/api/status');
    render(await r.json());
    document.getElementById('refresh-info').textContent =
      'last refresh: ' + new Date().toLocaleTimeString();
  } catch(e) {
    console.warn('refresh failed', e);
  }
}

async function triggerPoll(id) {
  const btn = document.getElementById('btn-' + id);
  if (btn) { btn.disabled = true; btn.textContent = '⏳ triggered'; }
  await fetch('/api/poll/' + id, { method: 'POST' });
  await refresh();
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""
