#!/bin/bash
# Task-executor service-agent test: agent-b runs an auto-accept worker loop
# that processes tasks from its queue and sends results back. agent-a
# submits tasks and retrieves correlated results via `pilotctl task result`.
#
# Also exercises the Polo score gate introduced recently: submitter's
# polo score must be >= receiver's. After one a->b round-trip the gate
# blocks a second submit until the flow is balanced by a b->a round-trip.

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

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Task-executor service-agent integration"
echo "=========================================="

log_test "Starting p2p stack (clean)"
docker compose -f docker-compose.multi.yml down -v >/dev/null 2>&1
docker compose -f docker-compose.multi.yml up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# ----- 1. Enable task execution on agent-b (the service agent) -----
log_test "enable-tasks on agent-b"
EN=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json enable-tasks 2>&1)
if echo "$EN" | jq -e '.data.task_exec == true' >/dev/null 2>&1; then
    log_pass "task_exec=true on agent-b"
else
    log_fail "enable-tasks failed: $(echo "$EN" | head -c 200)"
    exit 1
fi

# ----- 2. Worker loop on agent-b: auto-accept + send-results -----
# The worker polls `task list --type received` for NEW tasks and processes
# each one. `task queue` only surfaces tasks that have already been accepted
# so it's not the right signal for an auto-accept worker.
log_test "start auto-accept worker on agent-b"
rm -f /tmp/worker_stop 2>/dev/null
docker compose -f docker-compose.multi.yml exec -d agent-b bash -c '
rm -f /tmp/worker_stop
while [ ! -f /tmp/worker_stop ]; do
    LIST=$(pilotctl --json task list --type received 2>/dev/null)
    # Pick one NEW task at a time; inner loop handles multiple per poll.
    for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
        DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
        echo "$(date +%H:%M:%S.%N) accept tid=$TID desc=$DESC" >> /tmp/worker.log
        pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
        pilotctl task send-results --id "$TID" --results "done: $DESC" >>/tmp/worker.log 2>&1 || true
    done
    sleep 0.3
done
echo worker-exit >> /tmp/worker.log
'
sleep 1
log_pass "worker started on agent-b"

# ----- 3. Submit first task a -> b (polo: 0 >= 0, allowed) -----
log_test "agent-a submits T1 (polo should allow)"
SUBMIT=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "compute-fibonacci" 2>&1)
TID1=$(echo "$SUBMIT" | jq -r '.data.task_id // empty')
ACC=$(echo "$SUBMIT" | jq -r '.data.accepted')
if [ "$ACC" = "true" ] && [ -n "$TID1" ]; then
    log_pass "T1 submitted: $TID1"
else
    log_fail "T1 submit rejected: $(echo "$SUBMIT" | head -c 300)"
    exit 1
fi

# Wait for worker to auto-accept + send-results + for agent-a to mark completed.
T1_STATUS=""
for _ in $(seq 1 30); do
    LIST=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task list --type submitted 2>&1)
    T1_STATUS=$(echo "$LIST" | jq -r --arg t "$TID1" '.data.tasks[] | select(.task_id == $t) | .status')
    if echo "$T1_STATUS" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
log_test "T1 reaches completed/succeeded on submitter"
if echo "$T1_STATUS" | grep -qiE "completed|succeeded|done"; then
    log_pass "submitter sees T1 status=$T1_STATUS"
else
    log_fail "T1 did not complete (status=$T1_STATUS)"
fi

# ----- 4. pilotctl task result: retrieve T1's result payload -----
log_test "pilotctl task result returns correlated payload"
RES1=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task result "$TID1" 2>&1)
CONTENT=$(echo "$RES1" | jq -r '.data.content // empty')
if [ "$CONTENT" = "done: compute-fibonacci" ]; then
    log_pass "T1 result correlates: \"$CONTENT\""
else
    log_fail "T1 result mismatch: got \"$CONTENT\" (want \"done: compute-fibonacci\")"
fi

# ----- 5. Polo gate blocks a second a -> b submit (a=-1, b=+reward) -----
log_test "polo gate rejects second a -> b submit with too-low score"
SUBMIT2=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "should-be-blocked" 2>&1)
ACC2=$(echo "$SUBMIT2" | jq -r '.data.accepted')
MSG2=$(echo "$SUBMIT2" | jq -r '.data.message')
if [ "$ACC2" = "false" ] && echo "$MSG2" | grep -q "Polo score too low"; then
    log_pass "polo gate blocked with: $MSG2"
else
    log_fail "polo gate did not block (accepted=$ACC2 message=$MSG2)"
fi

# ----- 6. Reverse flow: b -> a (b has polo credit, a is receiver) -----
log_test "enable-tasks on agent-a for reverse flow"
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
# Start a worker on agent-a too so it can process b's tasks.
docker compose -f docker-compose.multi.yml exec -d agent-a bash -c '
rm -f /tmp/worker_stop
while [ ! -f /tmp/worker_stop ]; do
    LIST=$(pilotctl --json task list --type received 2>/dev/null)
    for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
        DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
        pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
        pilotctl task send-results --id "$TID" --results "done: $DESC" >>/tmp/worker.log 2>&1 || true
    done
    sleep 0.3
done
'
sleep 1

log_test "agent-b submits B1 to agent-a (should be allowed)"
SUBMITB=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task submit agent-a --task "reverse-task" 2>&1)
BTID=$(echo "$SUBMITB" | jq -r '.data.task_id // empty')
BACC=$(echo "$SUBMITB" | jq -r '.data.accepted')
if [ "$BACC" = "true" ] && [ -n "$BTID" ]; then
    log_pass "B1 submitted: $BTID"
else
    log_fail "B1 rejected: $(echo "$SUBMITB" | head -c 300)"
fi

# Wait for B1 to complete.
B_STATUS=""
for _ in $(seq 1 30); do
    LIST=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task list --type submitted 2>&1)
    B_STATUS=$(echo "$LIST" | jq -r --arg t "$BTID" '.data.tasks[] | select(.task_id == $t) | .status')
    if echo "$B_STATUS" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
log_test "B1 completes on agent-b"
if echo "$B_STATUS" | grep -qiE "completed|succeeded|done"; then
    log_pass "agent-b sees B1 status=$B_STATUS"
else
    log_fail "B1 did not complete (status=$B_STATUS)"
fi

# ----- 7. After balanced round-trip, a -> b should be allowed again -----
log_test "balanced exchange restores polo, a can submit again"
SUBMIT3=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "after-balance" 2>&1)
ACC3=$(echo "$SUBMIT3" | jq -r '.data.accepted')
TID3=$(echo "$SUBMIT3" | jq -r '.data.task_id // empty')
MSG3=$(echo "$SUBMIT3" | jq -r '.data.message')
if [ "$ACC3" = "true" ] && [ -n "$TID3" ]; then
    log_pass "post-balance submit accepted: $TID3"
else
    log_fail "post-balance submit rejected: accepted=$ACC3 message=$MSG3"
fi

# Give the worker a chance to process it so we can retrieve the result.
if [ "$ACC3" = "true" ]; then
    for _ in $(seq 1 20); do
        LIST=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task list --type submitted 2>&1)
        S=$(echo "$LIST" | jq -r --arg t "$TID3" '.data.tasks[] | select(.task_id == $t) | .status')
        if echo "$S" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 1
    done

    log_test "post-balance task result correlates"
    RES3=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task result "$TID3" 2>&1)
    C3=$(echo "$RES3" | jq -r '.data.content // empty')
    if [ "$C3" = "done: after-balance" ]; then
        log_pass "post-balance result correlates"
    else
        log_fail "post-balance result mismatch: \"$C3\""
    fi
fi

# ----- 8. task result for a non-existent id should not crash the daemon -----
log_test "pilotctl task result on missing id returns clean error"
RES_MISS=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task result "00000000-0000-0000-0000-000000000000" 2>&1)
if echo "$RES_MISS" | jq -e '.status == "error" or (.data.content // "") == ""' >/dev/null 2>&1; then
    log_pass "missing-id handled cleanly"
else
    log_fail "unexpected result for missing id: $(echo "$RES_MISS" | head -c 200)"
fi

# ----- 9. No panic/fatal in either daemon log during the workload -----
log_test "no panics/fatals in daemon logs"
BAD=$(docker compose -f docker-compose.multi.yml logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found panic/fatal entries: $BAD"
fi

# Cleanup workers
docker compose -f docker-compose.multi.yml exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
docker compose -f docker-compose.multi.yml exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Task-executor test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
