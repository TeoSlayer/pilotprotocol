#!/bin/bash
# Webhook exactly-once on receiver restart between task ACCEPTED and
# SUCCEEDED. This pins the at-most-once invariant for task.completed.
#
# Scenario:
#   1. Submit T1 from agent-a to agent-b.
#   2. Agent-b worker ACCEPTs T1 (status=ACCEPTED) — do NOT send results.
#   3. docker compose restart agent-b  (between ACCEPTED and SUCCEEDED)
#   4. Restart worker, drive T1 to SUCCEEDED.
#   5. Assert agent-a received exactly ONE task.completed webhook.
#
# EXPECTED: delta == 1 (never 0, never 2+). A delta of 2 means the
# completion was delivered, persisted, and re-emitted on restart —
# a duplicate-delivery bug. A delta of 0 means the event was dropped
# during the restart window.
#
# NOTE: task.completed is not yet wired in pkg/daemon — this test will fail
# on delta=0 until it is. That failure is the finding.

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
source ./webhook_helpers.sh
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
ensure_webhook_sink_ready || { log_fail "webhook-sink never came up"; exit 1; }
$DC up -d agent-a agent-b >/dev/null 2>&1
# Under run-all.sh -j 10 parallelism, docker exec round-trips against a
# busy daemon stretch the effective wall-clock — 60 iterations can land
# in <30s of real registration polling. Use 120 to give registration
# the same real budget under load.
for _ in $(seq 1 $((120 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-a pilotctl set-webhook "$SINK/a" >/dev/null 2>&1
log_pass "agent-a webhook set"

for _ in $(seq 1 10); do $DC exec -T webhook-sink test -f "$LOG" && break; sleep 1; done
BEFORE=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"task.completed\"' $LOG 2>/dev/null; true" | tail -1)

# --- 1. Submit T1 ---
log_test "submit T1 a->b"
OUT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "exactly-once" 2>&1)
TID=$(echo "$OUT" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "submit failed: $(echo "$OUT" | head -c 300)"; exit 1; }
log_pass "T1=$TID"

# --- 2. Half-worker: accept only, do NOT send results ---
log_test "agent-b accepts T1, no results yet"
$DC exec -T agent-b pilotctl task accept --id "$TID" >/dev/null 2>&1
sleep 2
PRE=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
[ "$PRE" = "ACCEPTED" ] && log_pass "status=ACCEPTED" || { log_fail "pre-status=$PRE"; exit 1; }

# --- 3. Restart agent-b mid-task ---
log_test "restart agent-b between ACCEPTED and SUCCEEDED"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 $((60 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    C=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$C" -ge 2 ] && break
    sleep 1
done
log_pass "agent-b back online"

# --- 4. Recovery worker drives T1 to COMPLETED ---
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop
    pilotctl ping agent-a --count 2 --timeout 3s >/dev/null 2>&1 || true
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\" or .status == \"ACCEPTED\") | .task_id"); do
            ST=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .status")
            [ "$ST" = "NEW" ] && pilotctl task accept --id "$TID" >/dev/null 2>&1
            pilotctl task send-results --id "$TID" --results "recovered" >/dev/null 2>&1 || true
        done
        sleep 0.3
    done
'

FINAL=""
for _ in $(seq 1 $((60 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    FINAL=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    echo "$FINAL" | grep -qiE "completed|succeeded|done" && break
    sleep 1
done
echo "$FINAL" | grep -qiE "completed|succeeded|done" && log_pass "T1 final status=$FINAL" || log_fail "T1 did not complete"

sleep 8

# --- 5. EXACTLY ONE task.completed webhook ---
AFTER=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"task.completed\"' $LOG 2>/dev/null; true" | tail -1)
DELTA=$((AFTER - BEFORE))
log_test "exactly ONE task.completed webhook after restart (delta=$DELTA)"
if [ "$DELTA" -eq 1 ]; then
    log_pass "exactly-once preserved across restart"
elif [ "$DELTA" -gt 1 ]; then
    log_fail "DUPLICATE DELIVERY: delta=$DELTA — webhook fired $DELTA times for one completion"
else
    log_fail "NO DELIVERY: delta=0 — event likely not wired, or lost during restart"
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
