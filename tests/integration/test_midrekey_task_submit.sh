#!/bin/bash
# Matrix 2 F-series: task submit while a rekey is in flight.
# Forces agent-b restart to invalidate the tunnel crypto on a's side,
# then immediately submits a task. Submit frame is the first outbound
# frame after the rekey — this is exactly the P1-009 shape.

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
echo "Mid-rekey: task submit (P1-009 regression)"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

log_test "fresh stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Warm tunnel
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 \
    || { log_fail "warm-up failed"; exit 1; }

log_test "restart agent-b (rekey)"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agent-b did not re-register"; exit 1; }
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
log_pass "agent-b back"

# Start auto-accept worker; it will also warm its own side if needed.
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "midrekey-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.25
    done
'

# Fire submit IMMEDIATELY, no warm-up on sender side — this is the P1-009 surface.
log_test "task submit a->b during rekey window"
S=$($DC exec -T agent-a bash -c "timeout 20 pilotctl --json task submit agent-b --task 'midrekey-task'" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty' 2>/dev/null)
if [ -z "$TID" ]; then
    log_fail "submit failed at the door: $(echo "$S" | head -c 300)"
else
    log_pass "submit accepted id=$TID"
fi

# Wait up to 60s for completion.
log_test "task reaches completion"
FINAL=""
for _ in $(seq 1 60); do
    FINAL=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
    log_pass "task completed mid-rekey (status=$FINAL)"
else
    log_fail "stuck at $FINAL — P1-009 regression (submit frame dropped in rekey window)"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
