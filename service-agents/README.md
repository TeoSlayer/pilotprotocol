# Service Agents

Self-contained Gemini-powered HTTP agents that plug into the Pilot Protocol overlay network via the `responder` binary. Each agent exposes a `/chat` endpoint; the responder dispatches incoming pilot messages to it and routes the reply back to the sender's inbox.

```
service-agents/
├── README.md          ← you are here
├── new-agent          ← scaffold script
├── _template/         ← base files copied by new-agent
└── examples/
    ├── pilot-agent/   ← pilotctl command assistant
    └── claw-audit/    ← OpenClaw security auditor
```

---

## Quickstart: create a new agent in 5 minutes

```bash
cd ~/web4/pilotprotocol/service-agents

# Scaffold a new agent (pick an unused port)
./new-agent weather-agent 8400 "Provides weather forecasts"

# Edit the two files that make your agent unique
$EDITOR weather-agent/agent/prompts.py   # system prompt
$EDITOR weather-agent/agent/tools.py     # tool functions

# Copy and fill in your Gemini key
cp weather-agent/.env.example weather-agent/.env
$EDITOR weather-agent/.env               # set GOOGLE_API_KEY=...

# Start the API
./weather-agent/start.sh
```

That's it for local use. Continue below to wire it into Pilot Protocol.

---

## Step-by-step

### 1. Scaffold

```
./new-agent <name> <port> "<description>" [--endpoint <name>]
```

| Argument | Example | Notes |
|---|---|---|
| `name` | `weather-agent` | Becomes the directory name |
| `port` | `8400` | Must be unique across all agents |
| `description` | `"Provides weather forecasts"` | Shown in API `/health` |
| `--endpoint` | `weather` | Command name in endpoints.yaml (default: derived from name) |

The script copies `_template/` into a new directory and substitutes all `{{PLACEHOLDER}}` strings. It prints a complete next-steps checklist when done.

---

### 2. Edit `agent/prompts.py`

Define the agent's personality and constraints. The entire file is:

```python
SYSTEM_PROMPT = """You are WeatherAgent. You provide weather forecasts...

## Rules
- Always cite the data source
...
"""
```

See `examples/pilot-agent/agent/prompts.py` for a real example.

---

### 3. Edit `agent/tools.py`

Add Python functions the agent can call (web APIs, file reads, shell commands, etc.).

```python
def get_weather(location: str) -> dict:
    """Fetch current weather for a location."""
    ...

TOOL_DEFINITIONS = [
    {
        "name": "get_weather",
        "description": "Get current weather for a location.",
        "parameters": {
            "type": "object",
            "properties": {
                "location": {"type": "string", "description": "City name or lat/lon"}
            },
            "required": ["location"],
        },
    },
]

TOOL_FUNCTIONS = {
    "get_weather": lambda args: get_weather(args["location"]),
}
```

Rules:
- Each function returns a plain `dict` — Gemini serializes it to JSON
- `TOOL_DEFINITIONS` uses the Gemini function-calling schema
- `TOOL_FUNCTIONS` maps name → callable that receives the `args` dict
- Never put empty strings in `"enum"` arrays — Gemini rejects them

---

### 4. Set your API key

```bash
cp <agent>/.env.example <agent>/.env
# Edit .env:
GOOGLE_API_KEY=AIza...
```

The key is loaded by `start.sh` and exported to the uvicorn process.

---

### 5. Start the agent API

```bash
# Foreground (development)
./<agent>/start.sh

# Background with pm2 (production)
pm2 start ./<agent>/start.sh --name <agent> --interpreter bash

# Test it's alive
curl http://localhost:<port>/health
curl "http://localhost:<port>/chat?message=hello"
```

The first run creates a `.venv` and installs `requirements.txt` automatically.

---

### 6. Register in `~/.pilot/endpoints.yaml`

The responder reads this file to know which pilot commands to dispatch to which HTTP endpoint.

```yaml
commands:
  - name: weather
    link: http://localhost:8400/chat
    arg_regex: "^(?P<message>.+)$"
```

Then restart the responder:

```bash
pm2 restart responder
# or if running directly:
pkill responder && responder -interval 5s -socket /tmp/pilot.sock
```

The `arg_regex` named capture groups become query parameters. `(?P<message>.+)` forwards the full body as `?message=<text>`. You can use multiple groups for structured commands:

```yaml
arg_regex: "^from (?P<from>.+) to (?P<to>.+)$"
# sends: /chat?from=NYC&to=LAX
```

---

### 7. Add a shell command

Add to `~/.zshrc` or `~/.bashrc`:

```zsh
# Generic helper (add once)
_service_agent_call() {
  local endpoint="$1"; shift
  local query="$*"
  [[ -z "$query" ]] && { echo "Usage: $endpoint \"query\"" >&2; return 1; }
  local before
  before=$(pilotctl --json inbox 2>/dev/null | python3 -c \
    "import json,sys; print(len(json.load(sys.stdin)['data']['messages']))" 2>/dev/null)
  before=${before:-0}
  pilotctl scriptorium "$endpoint" "$query" >/dev/null 2>&1
  local elapsed=0 result=""
  while [[ $elapsed -lt 90 ]]; do
    sleep 3; elapsed=$((elapsed+3))
    result=$(pilotctl --json inbox 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)['data']['messages']
if len(data) > ${before}:
    for m in reversed(data):
        if m['bytes'] < 10000 and m.get('from','').startswith('0:'):
            body = m.get('data', '')
            try: print(json.loads(body))
            except: print(body)
            break
" 2>/dev/null)
    [[ -n "$result" ]] && { echo "$result"; return 0; }
  done
  echo "(no reply — check: pilotctl inbox)" >&2; return 1
}

# Per-agent alias
weather() { _service_agent_call "weather" "$@"; }
```

Then: `source ~/.zshrc` and use `weather "Will it rain in London tomorrow?"`.

---

## Running the full Pilot Protocol stack

All binaries must be running for end-to-end delivery.

### Build the binaries

```bash
cd ~/web4/pilotprotocol

# CLI tool (used everywhere)
go build -o ~/.pilot/bin/pilotctl ./cmd/pilotctl

# Responder (runs on the node that hosts the agent)
go build -o ~/responder ./cmd/responder
```

### Start the local daemon

```bash
pilotctl daemon start --hostname <your-hostname>

# Verify
pilotctl daemon status
pilotctl info
```

### Start the responder (same node as the agent)

```bash
# Foreground
responder -interval 5s -socket /tmp/pilot.sock

# Or with pm2
pm2 start ~/responder --name responder -- -interval 5s -socket /tmp/pilot.sock
```

The responder polls its inbox every `-interval`, matches messages against `endpoints.yaml`, and dispatches to the matching HTTP endpoint.

### Remote node (scriptorium)

If the agent runs on a remote GCloud VM or server:

```bash
# On the remote node
pilotctl daemon start --hostname scriptorium --trust-auto-approve
pm2 restart responder
pm2 start ./service-agents/<agent>/start.sh --name <agent> --interpreter bash
```

The sender uses `pilotctl scriptorium <endpoint> "<message>"` to send. The scriptorium node's responder picks it up and dispatches to the local agent.

### Trust setup (one-time)

Both nodes must mutually trust each other before messages flow:

```bash
# From local machine — initiate
pilotctl handshake scriptorium "service agent access"

# On scriptorium — approve
pilotctl pending
pilotctl approve <node_id>

# On scriptorium — also initiate back
pilotctl handshake <local-hostname> "reciprocal trust"

# On local machine — approve
pilotctl pending
pilotctl approve <node_id>
```

---

## Message flow diagram

```
pilotctl scriptorium weather "Will it rain?"
        │
        ▼  data-exchange port 1001
 scriptorium daemon
        │
        ▼  responder polls inbox
 responder reads endpoints.yaml
        │
        ▼  HTTP GET
 http://localhost:8400/chat?message=Will+it+rain%3F
        │
        ▼
 weather-agent (Gemini + tools)
        │
        ▼  pilotctl send-message <sender>
 sender's inbox
        │
        ▼  _service_agent_call polls inbox
 reply printed to terminal
```

---

## The template structure

Every agent has the same shape — only `prompts.py`, `tools.py`, and `config.yaml` differ:

```
<agent-name>/
├── agent/
│   ├── gemini_agent.py    ← DO NOT EDIT (generic loop)
│   ├── prompts.py         ← EDIT: system prompt
│   └── tools.py           ← EDIT: tool functions
├── api/
│   └── server.py          ← DO NOT EDIT (generic FastAPI)
├── tui/
│   └── app.py             ← DO NOT EDIT (generic TUI)
├── config.yaml            ← EDIT: name, port, description, endpoint_name
├── requirements.txt       ← add agent-specific deps here
├── start.sh               ← DO NOT EDIT
└── .env                   ← create from .env.example, never commit
```

### `config.yaml` fields

```yaml
name: "weather-agent"           # display name
description: "Weather forecasts" # shown in /health
port: 8400                       # API port (unique per agent)
endpoint_name: "weather"         # command name in endpoints.yaml
endpoint_regex: "^(?P<message>.+)$"  # override if you need structured args
```

---

## API endpoints

Every agent exposes:

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check, returns name/port/description |
| `GET` | `/chat?message=<text>` | Single-turn chat (used by responder) |
| `POST` | `/chat` | JSON body `{"message": "...", "history": [...]}` |
| `POST` | `/stream` | SSE streaming chat |
| `GET` | `/stream?message=<text>` | SSE streaming (GET form) |

The TUI uses `/stream`. The responder uses `GET /chat`.

---

## Examples

See `examples/` for complete reference implementations:

- **`examples/pilot-agent/`** — translates natural language to `pilotctl` commands; reads pilotprotocol docs and source as tools
- **`examples/claw-audit/`** — OpenClaw security auditor; reads live config, checks permissions, scans for secrets; includes a 15-entry CVE-style vulnerability database

Each example directory contains only the agent-specific files (`config.yaml`, `agent/prompts.py`, `agent/tools.py`) — the rest comes from `_template/`.
