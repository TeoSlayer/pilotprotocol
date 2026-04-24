#!/bin/bash
set -euo pipefail

BIN="$HOME/.pilot/bin"
PILOT_EMAIL="${PILOT_EMAIL:-probe@vulturelabs.io}"
PILOT_HOSTNAME="${PILOT_HOSTNAME:-pilot-probe-$(hostname)}"
PILOT_REGISTRY="${PILOT_REGISTRY:-34.71.57.205:9000}"
PILOT_BEACON="${PILOT_BEACON:-34.71.57.205:9001}"

echo "[entrypoint] installing Pilot (hostname=$PILOT_HOSTNAME)"
curl -fsSL https://pilotprotocol.network/install.sh | \
  PILOT_EMAIL="$PILOT_EMAIL" \
  PILOT_HOSTNAME="$PILOT_HOSTNAME" \
  PILOT_REGISTRY="$PILOT_REGISTRY" \
  PILOT_BEACON="$PILOT_BEACON" \
  sh

export PATH="$BIN:$PATH"

echo "[entrypoint] installed: $(pilotctl version 2>/dev/null || echo unknown)"

rm -f /tmp/pilot.sock

echo "[entrypoint] starting pilot-daemon"
"$BIN/pilot-daemon" \
    -registry "$PILOT_REGISTRY" \
    -beacon "$PILOT_BEACON" \
    -listen :4000 \
    -socket /tmp/pilot.sock \
    -identity "$HOME/.pilot/identity.json" \
    -email "$PILOT_EMAIL" \
    -hostname "$PILOT_HOSTNAME" \
    -encrypt \
    >> "$HOME/.pilot/daemon.log" 2>&1 &
DAEMON_PID=$!
echo "[entrypoint] pilot-daemon pid=$DAEMON_PID"

if [ -x "$BIN/pilot-updater" ]; then
  echo "[entrypoint] starting pilot-updater"
  "$BIN/pilot-updater" -install-dir "$BIN" \
      >> "$HOME/.pilot/updater.log" 2>&1 &
  echo "[entrypoint] pilot-updater pid=$!"
fi

echo "[entrypoint] waiting for daemon ready"
for i in $(seq 1 60); do
    if pilotctl daemon status --check >/dev/null 2>&1; then
        echo "[entrypoint] daemon ready after ${i}s"
        break
    fi
    sleep 1
done

if ! pilotctl daemon status --check >/dev/null 2>&1; then
    echo "[entrypoint] daemon never became ready — daemon.log tail:"
    tail -40 "$HOME/.pilot/daemon.log" || true
    exit 1
fi

pilotctl info || true

for target in ${PILOT_PROBE_TARGETS:-pilot-agent-a,pilot-agent-b}; do
    for t in $(echo "$target" | tr ',' ' '); do
        echo "[entrypoint] handshake $t"
        pilotctl handshake "$t" "probe canary handshake" 2>&1 | head -3 || true
    done
done

echo "[entrypoint] launching probe loop"
exec python3 /opt/probe.py
