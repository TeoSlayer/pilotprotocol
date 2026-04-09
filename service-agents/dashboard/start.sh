#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PORT="${DASHBOARD_PORT:-7700}"
export PATH="$HOME/.pilot/bin:$PATH"
if [[ ! -d .venv ]]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt
fi
echo ""
echo "  Pilot Protocol Service Agent Dashboard"
echo "  → http://localhost:${PORT}"
echo "  pilotctl: $(which pilotctl 2>/dev/null || echo 'NOT FOUND')"
echo ""
exec .venv/bin/uvicorn server:app --host 0.0.0.0 --port "${PORT}" --log-level info
