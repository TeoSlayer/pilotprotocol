#!/bin/bash
# Webhook: task.submitted.
# Configure receiver (agent-b) to POST webhooks, submit one task a->b,
# and assert exactly one POST with .body.event == "task.submitted".
#
# EXPECTED: fires once per inbound task submission on the receiver.
# NOTE: grep of pkg/daemon shows no "task.submitted" emit site — expected
# failure until wired. That failure is the finding.

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
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous webhook-sink agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 $((120 * ${PILOT_TEST_WAIT_MULT:-1}))); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-b pilotctl set-webhook "$SINK/b" >/dev/null 2>&1
log_pass "agent-b tasks enabled + webhook set"

for _ in $(seq 1 10); do $DC exec -T webhook-sink test -f "$LOG" && break; sleep 1; done
BEFORE=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"task.submitted\"' $LOG 2>/dev/null; true" | tail -1)

log_test "agent-a submits one task to agent-b"
OUT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "webhook-test" 2>&1)
TID=$(echo "$OUT" | jq -r '.data.task_id // empty')
if [ -n "$TID" ]; then log_pass "submitted id=$TID"; else log_fail "submit failed: $(echo "$OUT" | head -c 300)"; exit 1; fi

sleep 8

AFTER=$($DC exec -T webhook-sink sh -c "grep -c '\"event\":\"task.submitted\"' $LOG 2>/dev/null; true" | tail -1)
DELTA=$((AFTER - BEFORE))
log_test "exactly one task.submitted webhook (delta=$DELTA)"
if [ "$DELTA" -eq 1 ]; then log_pass "task.submitted fired once"; else log_fail "expected delta=1 got $DELTA (event likely not wired)"; fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
