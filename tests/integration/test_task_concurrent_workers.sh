#!/bin/bash
# Concurrent-workers race: multiple auto-accept workers on the same agent-b
# poll the same received-task list. Only one should win the accept; the
# others should see invalid_state on their own accept attempt. The submitter
# should see exactly one final status and one result payload, regardless of
# how many workers raced.
#
# Exercises the `task accept` TOCTOU window: two workers can both read a NEW
# task and call `task accept` almost simultaneously — the second must fail
# with invalid_state. Without that check, parallel workers would both try to
# send-results and corrupt the submitter's view.

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
echo "Concurrent workers race integration"
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
    log_fail "agents did not register"
    exit 1
fi

docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# ----- 1. Start 3 workers racing the same queue on agent-b -----
# Each worker stamps its ID in the result content so we can tell which one
# won. Output goes to a shared /tmp/race.log so we can count accept
# outcomes post-mortem.
log_test "start 3 racing workers on agent-b"
for W in 1 2 3; do
    docker compose -f docker-compose.multi.yml exec -d agent-b bash -c "
        rm -f /tmp/worker_stop
        WID=$W
        while [ ! -f /tmp/worker_stop ]; do
            LIST=\$(pilotctl --json task list --type received 2>/dev/null)
            for TID in \$(echo \"\$LIST\" | jq -r '.data.tasks[]? | select(.status == \"NEW\") | .task_id'); do
                # Spin up accept + send-results; log outcome for both steps.
                AOUT=\$(pilotctl --json task accept --id \"\$TID\" 2>&1)
                AST=\$(echo \"\$AOUT\" | jq -r '.status // \"\"')
                echo \"\$(date +%H:%M:%S.%N) wid=\$WID tid=\$TID accept_status=\$AST\" >> /tmp/race.log
                if [ \"\$AST\" = \"ok\" ]; then
                    pilotctl task send-results --id \"\$TID\" --results \"winner=worker-\$WID\" >>/tmp/race.log 2>&1 || true
                fi
            done
            # Tight poll so workers collide on NEW tasks.
            sleep 0.05
        done
    "
done
sleep 1
log_pass "3 workers started"

# ----- 2. Submit a single task; wait for completion on submitter -----
log_test "agent-a submits T1 (3 workers will race)"
SUBMIT=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "one-job" 2>&1)
TID=$(echo "$SUBMIT" | jq -r '.data.task_id // empty')
if [ -n "$TID" ]; then
    log_pass "T1 submitted: $TID"
else
    log_fail "T1 submit rejected: $(echo "$SUBMIT" | head -c 200)"
    exit 1
fi

log_test "submitter sees T1 completed/succeeded within 20s"
FINAL=""
for _ in $(seq 1 20); do
    FINAL=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
    log_pass "submitter sees $FINAL"
else
    log_fail "task stuck at $FINAL"
fi

# Small settle before inspecting race log / file state.
sleep 2

# ----- 3. Exactly one worker should have succeeded at accept -----
log_test "exactly one accept_status=ok in race log"
OK_COUNT=$(docker compose -f docker-compose.multi.yml exec -T agent-b bash -c "grep -c 'accept_status=ok' /tmp/race.log 2>/dev/null" | tr -d '\r')
ERR_COUNT=$(docker compose -f docker-compose.multi.yml exec -T agent-b bash -c "grep -c 'accept_status=error' /tmp/race.log 2>/dev/null" | tr -d '\r')
# In a fast race all 3 workers may observe the NEW state; at minimum one
# winner + zero-or-more invalid_state errors. What we must NOT see is two
# accept_status=ok for the same TID.
DISTINCT_WINNERS=$(docker compose -f docker-compose.multi.yml exec -T agent-b bash -c "grep 'accept_status=ok' /tmp/race.log | awk '{print \$2\"_\"\$3}' | sort -u | wc -l" | tr -d '[:space:]')
if [ "$DISTINCT_WINNERS" = "1" ]; then
    log_pass "one winning (wid,tid) pair (ok=$OK_COUNT err=$ERR_COUNT)"
else
    log_fail "saw $DISTINCT_WINNERS distinct winners, expected 1 (ok=$OK_COUNT err=$ERR_COUNT)"
    docker compose -f docker-compose.multi.yml exec -T agent-b cat /tmp/race.log | tail -15
fi

# ----- 4. Submitter's result content should match exactly one winner -----
log_test "submitter's result correlates to a single worker"
RES=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task result "$TID" 2>&1)
CONTENT=$(echo "$RES" | jq -r '.data.content // empty')
if echo "$CONTENT" | grep -qE "^winner=worker-[123]$"; then
    log_pass "result is \"$CONTENT\" (single winner)"
else
    log_fail "unexpected result content: \"$CONTENT\""
fi

# ----- 5. No duplicate received-task file on agent-b -----
log_test "agent-b has exactly one task file for this TID"
COUNT=$(docker compose -f docker-compose.multi.yml exec -T agent-b bash -c "ls /root/.pilot/tasks/received/ 2>/dev/null | grep -c \"^$TID\"" | tr -d '[:space:]')
if [ "$COUNT" = "1" ]; then
    log_pass "received/ has a single file for $TID"
else
    log_fail "received/ has $COUNT files for $TID (expected 1)"
fi

# ----- 6. Submitter's received result file is a single file, not duplicated -----
log_test "submitter has exactly one result file for this TID"
RC=$(docker compose -f docker-compose.multi.yml exec -T agent-a bash -c "ls /root/.pilot/tasks/results/ 2>/dev/null | grep -c \"^${TID}_\"" | tr -d '[:space:]')
if [ "$RC" = "1" ]; then
    log_pass "results/ has 1 entry for $TID"
else
    log_fail "results/ has $RC entries for $TID (expected 1)"
fi

# ----- 7. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$(docker compose -f docker-compose.multi.yml logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

docker compose -f docker-compose.multi.yml exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Concurrent workers race test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
