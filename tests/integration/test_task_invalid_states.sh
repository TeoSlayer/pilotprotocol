#!/bin/bash
# Invalid state transitions on the tasksubmit service: these are
# negative-path tests that a hardened service agent would need the
# daemon to enforce. A misbehaving worker might send-results twice,
# try to accept a DECLINED task, execute after completion, etc. The
# daemon should reject each with invalid_state (or not_found) and
# never corrupt the submitter's view.
#
# Covers gaps left by test_task_decline.sh (which only checks
# decline-after-decline and decline-after-accept) and
# test_task_execute_flow.sh (which only checks execute-after-completion).

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
echo "Task invalid-state integration"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Helper: submit a task from agent-a to agent-b and echo the task id.
submit_from_a() {
    local desc=$1
    $DC exec -T agent-a pilotctl --json task submit agent-b --task "$desc" 2>/dev/null \
        | jq -r '.data.task_id // empty'
}

# ----- 1. send-results BEFORE accept must be rejected -----
log_test "send-results on NEW (not-yet-accepted) task is rejected"
TID1=$(submit_from_a "bad-send-results-before-accept")
if [ -z "$TID1" ]; then
    log_fail "could not submit T1"
    exit 1
fi
SR_NEW=$($DC exec -T agent-b pilotctl --json task send-results --id "$TID1" --results "too early" 2>&1)
if echo "$SR_NEW" | grep -qE "invalid_state|must be ACCEPTED|not accepted|not in accepted"; then
    log_pass "send-results-before-accept rejected"
else
    log_fail "unexpected: $(echo "$SR_NEW" | head -c 200)"
fi

# ----- 2. Double send-results on the SAME task -----
log_test "two back-to-back send-results; the second is rejected"
$DC exec -T agent-b pilotctl task accept --id "$TID1" >/dev/null 2>&1

SR1=$($DC exec -T agent-b pilotctl --json task send-results --id "$TID1" --results "first" 2>&1)
if ! echo "$SR1" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    log_fail "first send-results failed: $(echo "$SR1" | head -c 200)"
fi
SR2=$($DC exec -T agent-b pilotctl --json task send-results --id "$TID1" --results "second-should-not-overwrite" 2>&1)
if echo "$SR2" | grep -qE "invalid_state|already.*COMPLETED|already.*SUCCEEDED|not.*ACCEPTED"; then
    log_pass "second send-results rejected"
else
    log_fail "second send-results NOT rejected: $(echo "$SR2" | head -c 200)"
fi

# ----- 3. Submitter MUST see the FIRST result, not the second -----
# Wait for the completion to propagate to the submitter, then fetch.
log_test "submitter sees only the first result (no overwrite)"
for _ in $(seq 1 15); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID1" '.data.tasks[] | select(.task_id == $t) | .status')
    if echo "$ST" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
CONTENT=$($DC exec -T agent-a pilotctl --json task result "$TID1" 2>&1 | jq -r '.data.content // empty')
if [ "$CONTENT" = "first" ]; then
    log_pass "submitter has \"first\" — second call did not overwrite"
else
    log_fail "submitter got \"$CONTENT\" (want \"first\")"
fi

# ----- 4. accept on a DECLINED task must be rejected -----
# Polo gate: a already paid 1 on T1, so submitter might be blocked from
# submitting T2. Rebalance first by running a reverse task b -> a.
$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1

log_test "rebalance polo via a reverse b -> a round-trip"
$DC exec -d agent-a bash -c '
    rm -f /tmp/rebal_stop
    while [ ! -f /tmp/rebal_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >/dev/null 2>&1 || true
            pilotctl task send-results --id "$TID" --results "rebal-done" >/dev/null 2>&1 || true
        done
        sleep 0.3
    done
'
RTID=$($DC exec -T agent-b pilotctl --json task submit agent-a --task "rebal" 2>/dev/null | jq -r '.data.task_id // empty')
for _ in $(seq 1 15); do
    RST=$($DC exec -T agent-b pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$RTID" '.data.tasks[] | select(.task_id == $t) | .status')
    if echo "$RST" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
$DC exec -T agent-a touch /tmp/rebal_stop >/dev/null 2>&1
log_pass "rebalance complete"

log_test "accept on a DECLINED task is rejected"
TID2=$(submit_from_a "decline-then-accept")
if [ -z "$TID2" ]; then
    log_fail "could not submit T2"
else
    DEC=$($DC exec -T agent-b pilotctl --json task decline --id "$TID2" --justification "no" 2>&1)
    if ! echo "$DEC" | jq -e '.data.status == "DECLINED"' >/dev/null 2>&1; then
        log_fail "decline did not land: $(echo "$DEC" | head -c 200)"
    else
        ACC_ON_DECLINED=$($DC exec -T agent-b pilotctl --json task accept --id "$TID2" 2>&1)
        if echo "$ACC_ON_DECLINED" | grep -qE "invalid_state|already DECLINED|already.*declined"; then
            log_pass "accept-on-DECLINED rejected"
        else
            log_fail "unexpected: $(echo "$ACC_ON_DECLINED" | head -c 200)"
        fi
    fi
fi

# ----- 5. send-results on a DECLINED task must be rejected -----
log_test "send-results on a DECLINED task is rejected"
SR_ON_DECLINED=$($DC exec -T agent-b pilotctl --json task send-results --id "$TID2" --results "rogue" 2>&1)
if echo "$SR_ON_DECLINED" | grep -qE "invalid_state|DECLINED|not.*ACCEPTED"; then
    log_pass "send-results-on-DECLINED rejected"
else
    log_fail "unexpected: $(echo "$SR_ON_DECLINED" | head -c 200)"
fi

# ----- 6. accept on a completely unknown task-id is not_found -----
log_test "accept on unknown task-id returns not_found"
ACC_MISS=$($DC exec -T agent-b pilotctl --json task accept --id "00000000-0000-0000-0000-000000000000" 2>&1)
if echo "$ACC_MISS" | grep -qE "not_found|not found"; then
    log_pass "unknown-id accept rejected"
else
    log_fail "unexpected: $(echo "$ACC_MISS" | head -c 200)"
fi

# ----- 7. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Invalid-state test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
