#!/bin/bash
# Progress-reporting task executor: agent-b runs a worker that accepts a task,
# publishes N intermediate progress events on topic "progress", then sends
# results. agent-a submits the task AND subscribes to its own "progress"
# topic; the worker publishes progress to agent-a, so agent-a collects its
# own notifications.
#
# This is a different service-agent shape than test_task_executor.sh:
# there, the worker only interacts via the tasksubmit service. Here the
# worker is both a task-executor AND a pub/sub publisher, exercising two
# built-in services in the same worker loop. Catches bugs where:
#   - events published mid-task-RPC race against task state transitions
#   - the in-daemon event broker interferes with the task service on the
#     same daemon
#   - progress events get dropped when the publisher is the same agent
#     that holds the task's receiver-side files

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
echo "Task + progress events integration"
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

# ----- 1. Start subscriber on agent-a that collects 4 progress events -----
# Expected: 3 progress milestones + 1 "completed" marker per task.
log_test "start progress-event collector on agent-a (expects 4 events)"
$DC exec -d agent-a bash -c '
    pilotctl --json subscribe agent-a progress --count 4 --timeout 45s > /tmp/progress.log 2>&1
'
sleep 2
log_pass "collector launched"

# ----- 2. Start the progress-reporting worker on agent-b -----
# Worker: accept task -> publish 3 milestones to the submitter's "progress"
# topic -> send-results (task reaches COMPLETED) -> publish final "done".
# The submitter address is read from the NEW task's submitter_address field.
log_test "start progress-reporting worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker.log /tmp/worker_stop
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            # Submitter address field name varies across versions; fall back
            # to a fixed hostname if not readable from JSON.
            SUBMITTER=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | (.submitter_address // .from // \"\")")
            if [ -z "$SUBMITTER" ]; then
                SUBMITTER="agent-a"
            fi
            echo "$(date +%H:%M:%S.%N) accept tid=$TID submitter=$SUBMITTER" >> /tmp/worker.log
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            for STEP in 1 2 3; do
                pilotctl publish "$SUBMITTER" progress --data "progress:${TID}:${STEP}" >>/tmp/worker.log 2>&1 || true
                sleep 0.2
            done
            pilotctl task send-results --id "$TID" --results "done" >>/tmp/worker.log 2>&1 || true
            pilotctl publish "$SUBMITTER" progress --data "done:${TID}" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.2
    done
    echo worker-exit >> /tmp/worker.log
'
sleep 1
log_pass "worker started"

# ----- 3. agent-a submits the task -----
log_test "agent-a submits the progress task"
SUBMIT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "progress-scan" 2>&1)
TID=$(echo "$SUBMIT" | jq -r '.data.task_id // empty')
ACC=$(echo "$SUBMIT" | jq -r '.data.accepted')
if [ "$ACC" = "true" ] && [ -n "$TID" ]; then
    log_pass "submitted: $TID"
else
    log_fail "submit rejected: $(echo "$SUBMIT" | head -c 300)"
    exit 1
fi

# ----- 4. Wait for the task to complete on submitter -----
log_test "task reaches COMPLETED/SUCCEEDED on submitter"
STATUS=""
for _ in $(seq 1 30); do
    STATUS=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>&1 \
        | jq -r --arg t "$TID" '.data.tasks[] | select(.task_id == $t) | .status')
    if echo "$STATUS" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$STATUS" | grep -qiE "completed|succeeded|done"; then
    log_pass "task status=$STATUS"
else
    log_fail "task stuck at $STATUS"
fi

# ----- 5. Wait for collector to finish + assert 4 events received -----
log_test "collector gets all 4 progress events within timeout"
for _ in $(seq 1 50); do
    OUT=$($DC exec -T agent-a cat /tmp/progress.log 2>/dev/null)
    EVTS=$(echo "$OUT" | jq -r '.data.events | length' 2>/dev/null)
    # Bail early either on full count or on timeout flag.
    if [ "$EVTS" = "4" ] || echo "$OUT" | jq -e '.data.timeout == true' >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
OUT=$($DC exec -T agent-a cat /tmp/progress.log 2>/dev/null)
EVT_COUNT=$(echo "$OUT" | jq -r '.data.events | length' 2>/dev/null)
if [ "$EVT_COUNT" = "4" ]; then
    log_pass "collector got 4 events"
else
    log_fail "collector got $EVT_COUNT/4 events (timeout=$(echo "$OUT" | jq -r '.data.timeout // "?"'))"
    echo "$OUT" | head -c 500
    echo
    echo "worker log tail:"
    $DC exec -T agent-b tail -30 /tmp/worker.log 2>&1 | sed 's/^/  /'
fi

# ----- 6. Events correlate: each contains the task id, milestones 1..3 + done -----
log_test "progress events correlate to this task's id"
MATCHED=0
for STEP in 1 2 3; do
    if echo "$OUT" | jq -e --arg w "progress:${TID}:${STEP}" '.data.events[]? | select(.data == $w)' >/dev/null 2>&1; then
        MATCHED=$((MATCHED+1))
    fi
done
if echo "$OUT" | jq -e --arg w "done:${TID}" '.data.events[]? | select(.data == $w)' >/dev/null 2>&1; then
    MATCHED=$((MATCHED+1))
fi
if [ "$MATCHED" = "4" ]; then
    log_pass "all 4 events correlate to $TID"
else
    log_fail "only $MATCHED/4 events correlated"
fi

# ----- 7. Progress events arrive BEFORE or equal to the done marker (ordering) -----
# Ensures the broker preserves publication order for a single publisher.
log_test "progress:*:1 arrives before done:*"
ORDER_DATA=$(echo "$OUT" | jq -r '.data.events[].data' 2>/dev/null)
FIRST_DONE_LINE=$(echo "$ORDER_DATA" | grep -n "^done:" | head -1 | cut -d: -f1)
LAST_PROG_LINE=$(echo "$ORDER_DATA" | grep -n "^progress:" | tail -1 | cut -d: -f1)
if [ -n "$FIRST_DONE_LINE" ] && [ -n "$LAST_PROG_LINE" ] && [ "$LAST_PROG_LINE" -lt "$FIRST_DONE_LINE" ]; then
    log_pass "all progress:* precede done:* (last_prog=line $LAST_PROG_LINE, first_done=line $FIRST_DONE_LINE)"
else
    log_fail "ordering broken (last_prog=$LAST_PROG_LINE first_done=$FIRST_DONE_LINE)"
    echo "$ORDER_DATA" | sed 's/^/    /'
fi

# ----- 8. No panic/fatal in either daemon log -----
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
echo "Progress events test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
