#!/bin/bash
# Race: task submit concurrent with tunnel rekey (P1-009 direct repro).
#
# Restart agent-b to force a fresh crypto state on its side. Immediately
# submit a task from agent-a to agent-b before agent-a observes the restart
# and before a full key-exchange round trip completes. The first outbound
# tasksubmit frame travels through the rekey window. Per P1-009, the frame
# is silently dropped and the task status stays ACCEPTED forever on the
# submitter while the receiver has SUCCEEDED on disk.
#
# This test is EXPECTED TO FAIL until P1-009 ships a fix (either
# ack-on-send-results or VirtualConn tear-down on rekey).

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }

DC="docker compose -f docker-compose.multi.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Race: task submit across rekey window (P1-009)"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

$DC exec -T agent-b bash -c 'pilotctl enable-tasks' >/dev/null 2>&1

# Warm up the tunnel so agent-a caches agent-b's endpoint + crypto.
log_test "warm up tunnel (ping)"
$DC exec -T agent-a bash -c 'pilotctl ping agent-b --count 2 --timeout 5s' >/dev/null 2>&1
log_pass "warmed"

# Restart agent-b to invalidate its crypto state for agent-a.
log_test "restart agent-b (forces rekey on first frame from a)"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 30); do
    NID=$($DC exec -T agent-b bash -c 'pilotctl --json info 2>/dev/null' | jq -r '.data.node_id // empty' 2>/dev/null)
    [ -n "$NID" ] && [ "$NID" != "0" ] && [ "$NID" != "null" ] && break
    sleep 0.5
done
log_pass "agent-b back up, node_id=$NID"

# Submit immediately, without any warm-up ping. This is the critical window
# described in P1-009: the first tasksubmit frame triggers key exchange but
# the VirtualConn on agent-a is still bound to the stale pre-restart state.
log_test "immediately submit task across rekey window"
SUB=$($DC exec -T agent-a bash -c 'pilotctl --json task submit agent-b --task "rekey-race" --timeout 30s 2>&1')
TID=$(echo "$SUB" | jq -r '.data.task_id // empty')
if [ -n "$TID" ] && [ "$TID" != "null" ]; then
    log_pass "submit returned task_id=$TID"
else
    log_fail "submit failed: $(echo "$SUB" | head -c 300)"
fi

# Now the P1-009 check: the task must reach agent-b's received list, AND
# the round-trip result must propagate back to agent-a's submitted list as
# either SUCCEEDED or FAILED within a reasonable window. A stuck ACCEPTED
# forever is the bug signature.
log_test "task appears on agent-b received list"
RECV=""
for _ in $(seq 1 20); do
    RECV=$($DC exec -T agent-b bash -c "pilotctl --json task list --type received" | jq -r --arg id "$TID" '.data.tasks[]? | select(.task_id==$id) | .task_id' 2>/dev/null)
    [ -n "$RECV" ] && break
    sleep 0.5
done
if [ -n "$RECV" ]; then
    log_pass "agent-b sees task in received list"
else
    log_fail "agent-b never observed submitted task (rekey dropped the frame)"
fi

# Drive the full round-trip: accept + send-results from b, verify status
# reflects on a's submitted list within 30s.
$DC exec -T agent-b bash -c "pilotctl --json task accept --id $TID" >/dev/null 2>&1
$DC exec -T agent-b bash -c "pilotctl --json task send-results --id $TID --results 'done'" >/dev/null 2>&1

log_test "status transitions to SUCCEEDED on submitter within 30s (P1-009 gate)"
STATUS=""
for _ in $(seq 1 60); do
    STATUS=$($DC exec -T agent-a bash -c "pilotctl --json task list --type submitted" | jq -r --arg id "$TID" '.data.tasks[]? | select(.task_id==$id) | .status' 2>/dev/null)
    if [ "$STATUS" = "SUCCEEDED" ] || [ "$STATUS" = "FAILED" ]; then
        break
    fi
    sleep 0.5
done
if [ "$STATUS" = "SUCCEEDED" ]; then
    log_pass "P1-009: status propagated to SUCCEEDED"
elif [ "$STATUS" = "FAILED" ]; then
    log_fail "P1-009: reached FAILED instead of SUCCEEDED"
else
    log_fail "P1-009 repro: submitter stuck at status='$STATUS' (expected SUCCEEDED)"
fi

log_test "no panics in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
