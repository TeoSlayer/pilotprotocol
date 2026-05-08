#!/bin/bash
# Smoke regression: ping + send-message to list-agents after a daemon
# restart. Runs the canonical "ultimate functional test" called out in
# the simplification work — every Tier extraction step must pass this.
#
# Exit non-zero on any failure.
set -e

LOG=/Users/calinteodor/.pilot/pilot.log

echo "== build daemon + pilotctl =="
go build -o ~/.pilot/bin/pilot-daemon ./cmd/daemon
go build -o ~/.pilot/bin/pilotctl ./cmd/pilotctl
codesign --sign - --force ~/.pilot/bin/pilot-daemon ~/.pilot/bin/pilotctl 2>&1 | tail -1

echo "== restart =="
pilotctl daemon stop 2>&1 | tail -1 || true
sleep 2
rm -f /tmp/pilot.sock ~/.pilot/pilot.pid
> "$LOG" || true
pilotctl daemon start 2>&1 | tail -1 || true

# Poll up to 30s for daemon IPC to become ready. The daemon does many
# handshakes on boot; on slow networks 8s is insufficient.
for i in $(seq 1 30); do
  if pilotctl info 2>&1 | grep -q "Address:"; then
    echo "daemon ready after ${i}s"
    break
  fi
  sleep 1
done
pilotctl info 2>&1 | head -3

PASS=0
FAIL=0
FAILED_DETAIL=""

# ----- 5 cold pings (one packet each) -----
echo "== 5 cold pings =="
for i in 1 2 3 4 5; do
  R=$(timeout 12 pilotctl ping list-agents -n 1 2>&1)
  if echo "$R" | grep -q "bytes="; then
    PASS=$((PASS+1))
    echo "  ping $i: $(echo "$R" | grep bytes= | head -1)"
  else
    FAIL=$((FAIL+1))
    FAILED_DETAIL="$FAILED_DETAIL ping-$i"
    echo "  ping $i FAIL: $(echo "$R" | head -1)"
  fi
done

# ----- 5 send-message -----
echo "== 5 send-message =="
for i in 1 2 3 4 5; do
  R=$(timeout 10 pilotctl send-message list-agents --data "smoke-$i" 2>&1)
  if echo "$R" | grep -q '"ack"'; then
    PASS=$((PASS+1))
    echo "  send $i ok"
  else
    FAIL=$((FAIL+1))
    FAILED_DETAIL="$FAILED_DETAIL send-$i"
    echo "  send $i FAIL: $(echo "$R" | tr '\n' ' ' | cut -c1-150)"
  fi
done

echo
echo "== summary: $PASS/10 pass, $FAIL fail =="
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAILED_DETAIL"
  exit 1
fi
echo "SMOKE PASSED"
