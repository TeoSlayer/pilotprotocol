#!/bin/sh
# Auto-accept all pending Pilot Protocol trust requests.
# Polls every INTERVAL seconds and approves any incoming handshakes.
#
# Usage:
#   ./auto-accept.sh              # poll every 5s (default)
#   ./auto-accept.sh 10           # poll every 10s
#   PILOT_SOCKET=/tmp/pilot.sock ./auto-accept.sh

INTERVAL="${1:-5}"

while true; do
    PENDING=$(pilotctl --json pending 2>/dev/null)
    if [ $? -ne 0 ]; then
        sleep "$INTERVAL"
        continue
    fi

    echo "$PENDING" | grep -o '"node_id":[0-9]*' | grep -o '[0-9]*' | while read -r NODE_ID; do
        pilotctl approve "$NODE_ID" >/dev/null 2>&1 && \
            echo "approved node $NODE_ID"
    done

    sleep "$INTERVAL"
done
