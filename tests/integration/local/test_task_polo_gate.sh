#!/bin/bash
# Polo gate probe: TaskSubmit is rejected when the submitter's polo
# score is lower than the receiver's. This test exercises the gate
# directly and asserts the shape of the rejection + the recovery path:
#
#   1. Fresh stack: a.polo == b.polo == 0. Submit+complete T1 a->b.
#   2. Post-completion a.polo = -reward, b.polo = +reward on the
#      a<->b axis. Attempt T2 a->b: MUST be rejected by the polo gate
#      with accepted=false and a message that cites score/polo.
#   3. Rebalance by running a reverse round-trip b->a -> completed.
#      After completion the a<->b differential is closed.
#   4. Attempt T3 a->b again: MUST succeed.
#
# Targets regressions in the polo-gate logic: a faulty gate might
#   - let T2 through (polo ignored),
#   - reject T3 after rebalance (stuck gate),
#   - return an unhelpful error string that scripts/service agents
#     can't reliably detect.

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
echo "Polo gate rejection & recovery"
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

$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Helper: start an auto-accept worker on the given agent, logging to /tmp/worker.log.
start_worker() {
    local agent=$1
    $DC exec -d "$agent" bash -c '
        rm -f /tmp/worker_stop /tmp/worker.log
        while [ ! -f /tmp/worker_stop ]; do
            LIST=$(pilotctl --json task list --type received 2>/dev/null)
            for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
                DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
                pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
                pilotctl task send-results --id "$TID" --results "done:$DESC" >>/tmp/worker.log 2>&1 || true
            done
            sleep 0.15
        done
    '
}

wait_completed() {
    local agent=$1 tid=$2
    for _ in $(seq 1 30); do
        local s
        s=$($DC exec -T "$agent" pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$s" | grep -qiE "completed|succeeded|done"; then
            echo "$s"; return 0
        fi
        sleep 1
    done
    echo "$s"; return 1
}

# ----- Phase 1: a.polo == b.polo, submit+complete T1 a -> b ----------
log_test "start worker on agent-b; submit T1 a->b and wait for completion"
start_worker agent-b
sleep 1
S1=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "t1" 2>&1)
TID1=$(echo "$S1" | jq -r '.data.task_id // empty')
ACC1=$(echo "$S1" | jq -r '.data.accepted')
if [ "$ACC1" = "true" ] && [ -n "$TID1" ]; then
    ST1=$(wait_completed agent-a "$TID1")
    if echo "$ST1" | grep -qiE "completed|succeeded|done"; then
        log_pass "T1 completed (status=$ST1)"
    else
        log_fail "T1 did not complete (status=$ST1)"
        exit 1
    fi
else
    log_fail "T1 submit rejected: $(echo "$S1" | head -c 200)"
    exit 1
fi

# ----- Phase 2: T2 a -> b MUST be rejected by the polo gate ---------
log_test "T2 a->b is rejected by the polo gate (accepted=false)"
S2=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "t2" 2>&1)
ACC2=$(echo "$S2" | jq -r '.data.accepted')
MSG2=$(echo "$S2" | jq -r '.data.message // .message // empty')
if [ "$ACC2" = "false" ]; then
    log_pass "T2 rejected: accepted=false"
else
    log_fail "T2 unexpectedly landed: $(echo "$S2" | head -c 300)"
fi

# ----- Phase 3: rejection message cites the gate reason --------------
log_test "rejection message cites polo/score/balance"
if echo "$MSG2" | grep -qiE "polo|score|balance|lower|reputation"; then
    log_pass "gate message: $MSG2"
else
    log_fail "unhelpful rejection message: '$MSG2' (full response: $(echo "$S2" | head -c 300))"
fi

# ----- Phase 4: rebalance via reverse b -> a round-trip -------------
log_test "rebalance via b->a round-trip"
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
sleep 1
start_worker agent-a
sleep 1
R=$($DC exec -T agent-b pilotctl --json task submit agent-a --task "rebal" 2>&1)
RTID=$(echo "$R" | jq -r '.data.task_id // empty')
RACC=$(echo "$R" | jq -r '.data.accepted')
if [ "$RACC" = "true" ] && [ -n "$RTID" ]; then
    RST=$(wait_completed agent-b "$RTID")
    if echo "$RST" | grep -qiE "completed|succeeded|done"; then
        log_pass "rebalance done (status=$RST)"
    else
        log_fail "rebalance stuck (status=$RST)"
    fi
else
    log_fail "rebalance submit rejected: $(echo "$R" | head -c 200)"
fi

# Stop a-side worker, start b-side again for next submit.
$DC exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
sleep 1
start_worker agent-b
sleep 1

# ----- Phase 5: T3 a -> b now succeeds -----------------------------
log_test "T3 a->b succeeds after rebalance"
S3=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "t3" 2>&1)
TID3=$(echo "$S3" | jq -r '.data.task_id // empty')
ACC3=$(echo "$S3" | jq -r '.data.accepted')
if [ "$ACC3" = "true" ] && [ -n "$TID3" ]; then
    ST3=$(wait_completed agent-a "$TID3")
    if echo "$ST3" | grep -qiE "completed|succeeded|done"; then
        log_pass "T3 completed (status=$ST3)"
    else
        log_fail "T3 did not complete (status=$ST3)"
    fi
else
    log_fail "T3 submit rejected after rebalance: $(echo "$S3" | head -c 300)"
fi

# ----- Phase 6: task-list ids for t1 and t3 both visible on agent-a -
log_test "agent-a sees both t1 and t3 in submitted list"
LIST_A=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
HAS1=$(echo "$LIST_A" | jq -r --arg t "$TID1" '[.data.tasks[]? | select(.task_id == $t)] | length')
HAS3=$(echo "$LIST_A" | jq -r --arg t "$TID3" '[.data.tasks[]? | select(.task_id == $t)] | length')
if [ "$HAS1" = "1" ] && [ "$HAS3" = "1" ]; then
    log_pass "both t1 and t3 present"
else
    log_fail "list missing tasks: t1=$HAS1 t3=$HAS3"
fi

# ----- Phase 7: No panic/fatal --------------------------------------
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Polo gate test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
