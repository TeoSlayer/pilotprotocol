#!/bin/bash
# Race: task accept vs task submit.
#
# A worker on agent-b polls `task list --type received` at 10 ms intervals and
# attempts to accept any task it sees. Meanwhile agent-a submits a task. The
# race is: does the worker ever observe / try to accept a "ghost" task that
# doesn't actually exist on disk yet, or accept the same task twice?
#
# Expected: exactly one successful accept for the submitted task; no
# "task not found" surfacing to the user (the submit→accept window should be
# atomic from the worker's perspective), no panics.

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
echo "Race: task submit vs tight accept-poll loop"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

$DC exec -T agent-b bash -c 'pilotctl enable-tasks' >/dev/null 2>&1

# Start a tight poll-and-accept worker on agent-b BEFORE submission.
log_test "launch worker on agent-b polling at 10 ms"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker.log /tmp/worker_stop /tmp/accepted.ids
    : > /tmp/accepted.ids
    while [ ! -f /tmp/worker_stop ]; do
        out=$(pilotctl --json task list --type received 2>/dev/null)
        ids=$(echo "$out" | jq -r ".data.tasks[]? | select(.status==\"NEW\") | .task_id" 2>/dev/null)
        for id in $ids; do
            resp=$(pilotctl --json task accept --id "$id" 2>/dev/null)
            status=$(echo "$resp" | jq -r ".status // \"\"")
            err=$(echo "$resp" | jq -r ".error // \"\"")
            echo "$(date +%s.%N) id=$id status=$status err=$err" >>/tmp/worker.log
            if [ "$status" = "ok" ]; then
                echo "$id" >>/tmp/accepted.ids
            fi
        done
        # 10 ms poll
        sleep 0.01
    done
'

# Give the worker a moment to actually start polling.
sleep 0.3

log_test "agent-a submits single task"
SUB=$($DC exec -T agent-a bash -c 'pilotctl --json task submit agent-b --task "race-accept" 2>&1')
TID=$(echo "$SUB" | jq -r '.data.task_id // empty')
if [ -n "$TID" ] && [ "$TID" != "null" ]; then
    log_pass "submitted task id=$TID"
else
    log_fail "submit failed: $(echo "$SUB" | head -c 200)"
fi

# Give the worker time to observe and accept.
sleep 2

log_test "stop worker"
$DC exec -T agent-b bash -c 'touch /tmp/worker_stop'
sleep 0.5

log_test "exactly one successful accept for the task"
ACCS=$($DC exec -T agent-b bash -c "grep -c '^' /tmp/accepted.ids" 2>/dev/null | tr -d ' \r\n')
UNIQ=$($DC exec -T agent-b bash -c 'sort -u /tmp/accepted.ids | wc -l' | tr -d ' \r\n')
if [ "${ACCS:-0}" = "1" ] && [ "${UNIQ:-0}" = "1" ]; then
    log_pass "exactly one accept, no duplicate"
else
    log_fail "accepts=$ACCS unique=$UNIQ (want 1/1)"
    $DC exec -T agent-b bash -c 'tail -20 /tmp/worker.log' 2>&1 | sed 's/^/    /'
fi

log_test "no 'task not found' / ghost-accept errors"
GHOSTS=$($DC exec -T agent-b bash -c "grep -ciE 'task.*not.*found|no such task|ghost' /tmp/worker.log" 2>/dev/null | tr -d ' \r\n')
if [ "${GHOSTS:-0}" = "0" ]; then
    log_pass "no ghost-accept errors"
else
    log_fail "$GHOSTS ghost-accept errors in worker log"
    $DC exec -T agent-b bash -c "grep -iE 'not.*found|ghost' /tmp/worker.log | head -5" | sed 's/^/    /'
fi

log_test "no panics in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
