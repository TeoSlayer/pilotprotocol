#!/bin/bash
# Matrix 2 F-series: force relay, submit + complete task.
# P1-010 likely affects the submit frame here; authored per spec.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"

cd "$(dirname "$0")" || exit 1
# shellcheck source=chaos_helpers.sh
source ./chaos_helpers.sh

echo "=========================================="
echo "Force relay: task submit+complete"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1 || true
    heal_partition agent-a "$IP_B" >/dev/null 2>&1 || true
    heal_partition agent-b "$IP_A" >/dev/null 2>&1 || true
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

IP_A=$(resolve_service_ip agent-a)
IP_B=$(resolve_service_ip agent-b)

$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Start auto-worker BEFORE partitioning so its internal state is healthy.
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "relay-task-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.25
    done
'

log_test "partition direct UDP"
apply_partition agent-a "$IP_B"
apply_partition agent-b "$IP_A"
log_pass "direct severed"

sleep 10

log_test "task submit a->b via relay"
S=$($DC exec -T agent-a bash -c "timeout 60 pilotctl --json task submit agent-b --task 'relay-task'" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
if [ -z "$TID" ]; then
    log_fail "submit failed at door: $(echo "$S" | head -c 300)"
else
    log_pass "submit accepted id=$TID"
fi

log_test "task reaches completion via relay"
FINAL=""
for _ in $(seq 1 90); do
    FINAL=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
    log_pass "task completed via relay (status=$FINAL)"
else
    log_fail "stuck at $FINAL — likely P1-010"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
