#!/usr/bin/env bash
# Generic service agent startup script.
# DO NOT EDIT — configure via config.yaml and agent/prompts.py + agent/tools.py.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env if present (GOOGLE_API_KEY, GEMINI_API_KEY, etc.)
if [[ -f .env ]]; then
    set -a; source .env; set +a
fi

# Read config.yaml
_py() { python3 -c "import yaml,sys; d=yaml.safe_load(open('config.yaml')); print(d$1)" 2>/dev/null; }
AGENT_NAME=$(_py "['name']")
AGENT_PORT=$(_py "['port']")
AGENT_DESCRIPTION=$(_py "['description']")

export AGENT_NAME AGENT_PORT AGENT_DESCRIPTION

# Bootstrap venv on first run
if [[ ! -d .venv ]]; then
    echo "[$AGENT_NAME] creating venv..."
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi

echo "[$AGENT_NAME] starting on port $AGENT_PORT"
exec .venv/bin/uvicorn api.server:app \
    --host 127.0.0.1 \
    --port "$AGENT_PORT" \
    --log-level info
