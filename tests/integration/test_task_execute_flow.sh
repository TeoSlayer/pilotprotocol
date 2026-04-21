#!/bin/bash
# Task-execute lifecycle: exercises the explicit `pilotctl task execute`
# command — a worker that decouples accept from execution. Unlike the
# executor test which collapses accept+send-results, this one drives the
# state machine NEW -> ACCEPTED -> EXECUTING -> SUCCEEDED via distinct
# CLI invocations and verifies the EXECUTING status update propagates to
# the submitter.
#
# Failure modes this catches:
#  - `task execute` errors cleanly when nothing is in the ACCEPTED state
#    (both "no tasks at all" and "only NEW tasks" cases)
#  - the EXECUTING status update round-trips to the submitter's task list
#  - `task queue` correctly reflects queue state across transitions (shows
#    ACCEPTED tasks, excludes EXECUTING/COMPLETED)
#  - global daemon queue entry is removed on execute (no zombie entries)

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
echo "Task execute lifecycle integration"
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
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

submitter_status() {
    local tid=$1
    $DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status'
}

# ----- 1. execute with no received tasks at all -----
log_test "task execute errors when no tasks received"
OUT=$($DC exec -T agent-b pilotctl --json task execute 2>&1)
CODE=$(echo "$OUT" | jq -r '.code // empty')
if [ "$CODE" = "not_found" ]; then
    log_pass "execute rejected (code=not_found)"
else
    log_fail "unexpected: $(echo "$OUT" | head -c 200)"
fi

# ----- 2. submit T1 so b has a NEW-but-unaccepted task -----
log_test "agent-a submits T1"
SUB=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "lifecycle-one" 2>&1)
TID=$(echo "$SUB" | jq -r '.data.task_id // empty')
if [ -n "$TID" ]; then
    log_pass "T1: $TID"
else
    log_fail "T1 submit failed: $(echo "$SUB" | head -c 200)"
    exit 1
fi

# ----- 3. execute with only NEW (not accepted) → still not_found -----
log_test "task execute rejects when only NEW tasks exist"
OUT=$($DC exec -T agent-b pilotctl --json task execute 2>&1)
CODE=$(echo "$OUT" | jq -r '.code // empty')
if [ "$CODE" = "not_found" ]; then
    log_pass "execute requires ACCEPTED, not NEW (code=not_found)"
else
    log_fail "unexpected: $(echo "$OUT" | head -c 200)"
fi

# ----- 4. accept T1 → ACCEPTED -----
log_test "agent-b accepts T1"
ACC=$($DC exec -T agent-b pilotctl --json task accept --id "$TID" 2>&1)
if echo "$ACC" | jq -e '.data.status == "ACCEPTED"' >/dev/null 2>&1; then
    log_pass "T1 ACCEPTED"
else
    log_fail "accept failed: $(echo "$ACC" | head -c 200)"
    exit 1
fi

# ----- 5. task queue shows T1 as queued -----
log_test "task queue shows T1 as queued"
Q=$($DC exec -T agent-b pilotctl --json task queue 2>&1)
IN_Q=$(echo "$Q" | jq -r --arg t "$TID" '.data.queue[]? | select(.task_id == $t) | .task_id')
if [ "$IN_Q" = "$TID" ]; then
    log_pass "T1 is in the queue"
else
    log_fail "T1 not in queue output: $(echo "$Q" | head -c 200)"
fi

# ----- 6. execute → EXECUTING with details -----
log_test "task execute transitions ACCEPTED → EXECUTING"
EX=$($DC exec -T agent-b pilotctl --json task execute 2>&1)
EX_TID=$(echo "$EX" | jq -r '.data.task_id // empty')
EX_STATUS=$(echo "$EX" | jq -r '.data.status // empty')
EX_FROM=$(echo "$EX" | jq -r '.data.from // empty')
EX_DESC=$(echo "$EX" | jq -r '.data.task_description // empty')
if [ "$EX_TID" = "$TID" ] && [ "$EX_STATUS" = "EXECUTING" ] && [ -n "$EX_FROM" ] && [ "$EX_DESC" = "lifecycle-one" ]; then
    log_pass "execute returned EXECUTING with full details"
else
    log_fail "execute payload off: tid=$EX_TID status=$EX_STATUS from=$EX_FROM desc=$EX_DESC"
fi

# ----- 7. task queue no longer includes T1 -----
log_test "task queue is empty after execute"
Q2=$($DC exec -T agent-b pilotctl --json task queue 2>&1)
IN_Q2=$(echo "$Q2" | jq -r --arg t "$TID" '.data.queue[]? | select(.task_id == $t) | .task_id')
if [ -z "$IN_Q2" ]; then
    log_pass "T1 is no longer in queue"
else
    log_fail "T1 still queued after execute: $Q2"
fi

# ----- 8. task list shows EXECUTING on b -----
log_test "task list on b shows EXECUTING"
LIST_B=$($DC exec -T agent-b pilotctl --json task list --type received 2>&1)
B_STATUS=$(echo "$LIST_B" | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
if [ "$B_STATUS" = "EXECUTING" ]; then
    log_pass "receiver sees EXECUTING"
else
    log_fail "receiver status=$B_STATUS (want EXECUTING)"
fi

# ----- 9. submitter sees EXECUTING within 10s -----
log_test "submitter sees EXECUTING within 10s"
A_STATUS=""
for _ in $(seq 1 10); do
    A_STATUS=$(submitter_status "$TID")
    if [ "$A_STATUS" = "EXECUTING" ]; then break; fi
    sleep 1
done
if [ "$A_STATUS" = "EXECUTING" ]; then
    log_pass "submitter sees EXECUTING"
else
    log_fail "submitter status=$A_STATUS (want EXECUTING)"
fi

# ----- 10. send results → SUCCEEDED -----
log_test "agent-b sends results"
SR=$($DC exec -T agent-b pilotctl --json task send-results --id "$TID" --results "ok" 2>&1)
if echo "$SR" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    log_pass "send-results accepted"
else
    log_fail "send-results failed: $(echo "$SR" | head -c 200)"
fi

log_test "submitter sees terminal status within 15s"
FINAL=""
for _ in $(seq 1 15); do
    FINAL=$(submitter_status "$TID")
    if echo "$FINAL" | grep -qiE "succeeded|completed|done"; then break; fi
    sleep 1
done
if echo "$FINAL" | grep -qiE "succeeded|completed|done"; then
    log_pass "submitter sees $FINAL"
else
    log_fail "submitter status=$FINAL"
fi

# ----- 11. execute again → not_found (nothing in ACCEPTED state) -----
log_test "task execute after completion → not_found"
OUT=$($DC exec -T agent-b pilotctl --json task execute 2>&1)
CODE=$(echo "$OUT" | jq -r '.code // empty')
if [ "$CODE" = "not_found" ]; then
    log_pass "execute correctly rejects when nothing accepted"
else
    log_fail "unexpected: $(echo "$OUT" | head -c 200)"
fi

# ----- 12. No panics/fatals in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Task execute lifecycle test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
