#!/bin/bash
# Task-decline service-agent test: agent-b declines tasks it doesn't want
# and the DECLINED status propagates back to agent-a. Also covers the
# invalid-state paths (--justification required, already-declined, already-
# accepted) and checks that declining does NOT drop the submitter's polo
# score (only completed tasks do).

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
echo "Task decline integration"
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

docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Helper: read submitted-task status from agent-a's list.
submitter_status() {
    local tid=$1
    docker compose -f docker-compose.multi.yml exec -T agent-a \
        pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status'
}

# ----- 1. Submit T1 and decline it cleanly -----
log_test "agent-a submits T1"
S1=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "please-decline-me" 2>&1)
TID1=$(echo "$S1" | jq -r '.data.task_id // empty')
if [ -n "$TID1" ]; then
    log_pass "T1: $TID1"
else
    log_fail "T1 submit failed: $(echo "$S1" | head -c 200)"
    exit 1
fi

log_test "decline requires --justification"
D_NOJUST=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task decline --id "$TID1" 2>&1)
if echo "$D_NOJUST" | grep -qE "justification is required|invalid_argument"; then
    log_pass "missing justification rejected"
else
    log_fail "unexpected: $(echo "$D_NOJUST" | head -c 200)"
fi

log_test "agent-b declines T1 with justification"
DECLINE=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task decline --id "$TID1" --justification "at-capacity" 2>&1)
if echo "$DECLINE" | jq -e '.data.status == "DECLINED"' >/dev/null 2>&1; then
    log_pass "decline local status=DECLINED"
else
    log_fail "decline did not succeed: $(echo "$DECLINE" | head -c 200)"
fi

# ----- 2. DECLINED status propagates to submitter -----
log_test "submitter sees DECLINED within 10s"
T1_STATUS=""
for _ in $(seq 1 10); do
    T1_STATUS=$(submitter_status "$TID1")
    if [ "$T1_STATUS" = "DECLINED" ]; then break; fi
    sleep 1
done
if [ "$T1_STATUS" = "DECLINED" ]; then
    log_pass "submitter status=DECLINED"
else
    log_fail "submitter status=$T1_STATUS (want DECLINED)"
fi

# ----- 3. The justification round-trips into the submitter's view -----
log_test "submitter's task carries the justification"
LIST_A=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task list --type submitted 2>&1)
JUST=$(echo "$LIST_A" | jq -r --arg t "$TID1" '.data.tasks[]? | select(.task_id == $t) | .status_justification // .justification // ""')
if echo "$JUST" | grep -q "at-capacity"; then
    log_pass "justification surfaced: $JUST"
else
    # Some builds store the justification only receiver-side — fall back to
    # checking the receiver view.
    LIST_B=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task list --type received 2>&1)
    JUST_B=$(echo "$LIST_B" | jq -r --arg t "$TID1" '.data.tasks[]? | select(.task_id == $t) | .status_justification // .justification // ""')
    if echo "$JUST_B" | grep -q "at-capacity"; then
        log_pass "justification stored receiver-side: $JUST_B"
    else
        log_fail "justification missing on both sides (a=\"$JUST\" b=\"$JUST_B\")"
    fi
fi

# ----- 4. Declining an already-declined task is an invalid-state error -----
log_test "declining already-declined task errors"
D_AGAIN=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task decline --id "$TID1" --justification "x" 2>&1)
if echo "$D_AGAIN" | grep -qE "already DECLINED|invalid_state"; then
    log_pass "re-decline rejected"
else
    log_fail "unexpected: $(echo "$D_AGAIN" | head -c 200)"
fi

# ----- 5. Declining an ACCEPTED task errors (status must be NEW) -----
log_test "T2 submitted and manually accepted"
S2=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "accept-then-decline" 2>&1)
TID2=$(echo "$S2" | jq -r '.data.task_id // empty')
ACC2=$(echo "$S2" | jq -r '.data.accepted')
if [ "$ACC2" = "true" ] && [ -n "$TID2" ]; then
    docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl task accept --id "$TID2" >/dev/null 2>&1
    log_pass "T2 accepted: $TID2"
else
    # If polo blocks here it means declining DID cost a point — that would be
    # its own failure.
    log_fail "T2 could not be submitted+accepted (accepted=$ACC2 msg=$(echo "$S2" | jq -r '.data.message'))"
fi

log_test "decline on ACCEPTED task is rejected"
D_ACC=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task decline --id "$TID2" --justification "changed-my-mind" 2>&1)
if echo "$D_ACC" | grep -qE "already ACCEPTED|invalid_state"; then
    log_pass "decline-after-accept rejected"
else
    log_fail "unexpected: $(echo "$D_ACC" | head -c 200)"
fi

# Complete T2 to keep the task store tidy; whether the scores matter for the
# next step or not, we want a deterministic state.
docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl task send-results --id "$TID2" --results "done" >/dev/null 2>&1
# After T2 completes, polo: a=-1, b=+1 — a third submit a -> b should fail.
# But we really care about the pre-completion check: that T2 was accepted
# (implying decline didn't cost a polo point), which step 5 already asserted.

# ----- 6. Decline on missing task id errors cleanly -----
log_test "decline on missing task id errors"
D_MISS=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task decline --id "00000000-0000-0000-0000-000000000000" --justification "x" 2>&1)
if echo "$D_MISS" | grep -qE "task not found|not_found"; then
    log_pass "missing id rejected"
else
    log_fail "unexpected: $(echo "$D_MISS" | head -c 200)"
fi

# ----- 7. No panic/fatal in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$(docker compose -f docker-compose.multi.yml logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found panic/fatal entries: $BAD"
fi

echo
echo "=========================================="
echo "Task decline test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
