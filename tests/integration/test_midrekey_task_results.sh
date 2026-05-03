#!/bin/bash
# Matrix 2 F-series: task RESULTS sent while a rekey is in flight.
# This is the classical P1-009 shape: a submits T, b accepts, b
# restarts (rekey), b then immediately sends results without a
# warm-up. The known-good workaround (ping to warm the tunnel) is
# deliberately omitted here so the test surfaces the bug.

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
echo "Mid-rekey: task results (P1-009 direct)"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
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
log_pass "agents up"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# ----- submit + accept (but do NOT send results yet) -----
log_test "submit + accept T1"
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "midrekey-results" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "submit failed: $(echo "$S" | head -c 300)"; exit 1; }
$DC exec -T agent-b pilotctl task accept --id "$TID" >/dev/null 2>&1
sleep 1
PRE=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
if [ "$PRE" = "ACCEPTED" ]; then
    log_pass "T1 ACCEPTED on b"
else
    log_fail "expected ACCEPTED, got $PRE"
    exit 1
fi

# ----- restart agent-b to force the rekey window -----
log_test "restart agent-b (rekey)"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agent-b did not re-register"; exit 1; }
log_pass "agent-b back, tunnel rekey window open"

# ----- send-results IMMEDIATELY (no warm-up ping on purpose) -----
# test_task_accepted_restart_recovery.sh has the workaround baked in;
# here we assert the RAW behavior. P1-009 prediction: submitter stays
# ACCEPTED forever.
log_test "send-results during rekey window (no warm-up)"
$DC exec -T agent-b bash -c "timeout 10 pilotctl task send-results --id $TID --results 'mid-rekey-delivered'" \
    >/tmp/sr.out 2>&1 || true

log_test "submitter observes terminal status within 45s"
FINAL=""
for _ in $(seq 1 45); do
    FINAL=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
    log_pass "results landed (status=$FINAL)"
else
    log_fail "stuck at $FINAL — direct P1-009 regression"
fi

# Result payload must equal what b sent.
log_test "result text matches sender payload"
RES=$($DC exec -T agent-a pilotctl --json task result --id "$TID" 2>/dev/null)
if echo "$RES" | jq -r '.data.content // empty' | grep -q "mid-rekey-delivered"; then
    log_pass "result payload matches"
else
    log_fail "payload missing: $(echo "$RES" | head -c 300)"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
