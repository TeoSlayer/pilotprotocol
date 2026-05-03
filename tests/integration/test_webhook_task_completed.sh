#!/bin/bash
# Webhook: task.completed.
# Submit a task, worker accepts+completes it, assert exactly one
# .body.event == "task.completed" POST on the submitter (agent-a).
#
# EXPECTED: fires once per task reaching the terminal COMPLETED/SUCCEEDED
# state on the submitter side.
# NOTE: grep of pkg/daemon shows no "task.completed" emit site — expected
# failure until wired.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.webhooks.yml"
SINK="http://webhook-sink:18080"
LOG="/var/log/webhooks.jsonl"

cd "$(dirname "$0")" || exit 1
cleanup() {
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous webhook-sink agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-a pilotctl set-webhook "$SINK/a" >/dev/null 2>&1
log_pass "agent-a webhook set (submitter observes completion)"

# Start worker loop on agent-b (accept + send-results).
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "done" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.3
    done
'

for _ in $(seq 1 10); do $DC exec -T webhook-sink test -f "$LOG" && break; sleep 1; done
BEFORE=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"task.completed\"' $LOG 2>/dev/null || echo 0")

log_test "agent-a submits one task, waits for completion"
OUT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "complete-me" 2>&1)
TID=$(echo "$OUT" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "submit failed: $(echo "$OUT" | head -c 300)"; exit 1; }

for _ in $(seq 1 60); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    echo "$ST" | grep -qiE "completed|succeeded|done" && break
    sleep 1
done
log_pass "task reached status=$ST"

sleep 6

AFTER=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"task.completed\"' $LOG 2>/dev/null || echo 0")
DELTA=$((AFTER - BEFORE))
log_test "exactly one task.completed webhook (delta=$DELTA)"
if [ "$DELTA" -eq 1 ]; then log_pass "task.completed fired once"; else log_fail "expected delta=1 got $DELTA (event likely not wired)"; fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
