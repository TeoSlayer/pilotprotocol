#!/bin/bash
# Bidirectional simultaneous task-executor service agents: both agents run
# auto-accept workers AND each submits a task to the other at the same time.
# This exercises concurrent task processing on each daemon (own submit path
# + own worker path hitting the same `.pilot/tasks/` tree) and makes sure
# the polo gate, task correlation, and result retrieval all work when the
# two flows interleave.
#
# Specifically catches bugs where:
#  - submitter-side and receiver-side code paths race on the same taskID
#    stored under ~/.pilot/tasks/submitted vs received (file naming
#    collisions would show up as missing results)
#  - polo score updates from one direction clobber the other when both
#    complete near-simultaneously
#  - a worker that is ALSO a submitter ends up accepting its OWN submitted
#    task (accidentally reading from submitted/ instead of received/)

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
echo "Bidirectional task services integration"
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

# ----- 1. Enable tasks on both sides -----
log_test "enable-tasks on both agents"
$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
log_pass "enable-tasks ok"

# ----- 2. Start a worker on BOTH agents at the same time -----
# Worker logic: poll `task list --type received`, auto-accept NEW tasks,
# send-results with a tag identifying which agent processed the task.
# Crucially: the worker must ONLY accept RECEIVED tasks, never its own
# SUBMITTED tasks — if the state machine mixes them up, we'd see the
# submitter accepting its own task.
start_worker() {
    local agent=$1 tag=$2
    $DC exec -d "$agent" bash -c "
        rm -f /tmp/worker_stop /tmp/worker.log
        while [ ! -f /tmp/worker_stop ]; do
            LIST=\$(pilotctl --json task list --type received 2>/dev/null)
            for TID in \$(echo \"\$LIST\" | jq -r '.data.tasks[]? | select(.status == \"NEW\") | .task_id'); do
                DESC=\$(echo \"\$LIST\" | jq -r --arg t \"\$TID\" '.data.tasks[] | select(.task_id == \$t) | .description')
                echo \"\$(date +%H:%M:%S.%N) $tag accept tid=\$TID desc=\$DESC\" >> /tmp/worker.log
                pilotctl task accept --id \"\$TID\" >>/tmp/worker.log 2>&1 || true
                pilotctl task send-results --id \"\$TID\" --results \"done-by-$tag:\$DESC\" >>/tmp/worker.log 2>&1 || true
            done
            sleep 0.15
        done
        echo worker-exit >> /tmp/worker.log
    "
}
log_test "start workers on both agents (workers do not touch submitted/)"
start_worker agent-a A
start_worker agent-b B
sleep 1
log_pass "two workers running"

# ----- 3. Both agents submit to the other simultaneously -----
# Use a shared barrier via `sleep` alignment — both agents exec from the
# host in parallel and the time skew should be tens of ms.
log_test "agent-a and agent-b submit to each other in parallel"
RES_A=$(mktemp)
RES_B=$(mktemp)
$DC exec -T agent-a pilotctl --json task submit agent-b --task "A-to-B" >"$RES_A" 2>&1 &
$DC exec -T agent-b pilotctl --json task submit agent-a --task "B-to-A" >"$RES_B" 2>&1 &
wait

TID_AB=$(jq -r '.data.task_id // empty' <"$RES_A")
ACC_AB=$(jq -r '.data.accepted' <"$RES_A")
TID_BA=$(jq -r '.data.task_id // empty' <"$RES_B")
ACC_BA=$(jq -r '.data.accepted' <"$RES_B")

if [ "$ACC_AB" = "true" ] && [ -n "$TID_AB" ] && [ "$ACC_BA" = "true" ] && [ -n "$TID_BA" ]; then
    log_pass "parallel submits accepted (A->B=$TID_AB, B->A=$TID_BA)"
else
    log_fail "parallel submit failed: A->B(acc=$ACC_AB msg=$(jq -r '.data.message' <"$RES_A")) B->A(acc=$ACC_BA msg=$(jq -r '.data.message' <"$RES_B"))"
    rm -f "$RES_A" "$RES_B"
    exit 1
fi
rm -f "$RES_A" "$RES_B"

# ----- 4. Both tasks reach COMPLETED on their respective submitters -----
log_test "A->B completes on agent-a AND B->A completes on agent-b (30s)"
wait_for_done() {
    local agent=$1 tid=$2
    for _ in $(seq 1 30); do
        local s
        s=$($DC exec -T "$agent" pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$s" | grep -qiE "completed|succeeded|done"; then
            echo "$s"
            return 0
        fi
        sleep 1
    done
    echo "$s"
    return 1
}

ST_AB=$(wait_for_done agent-a "$TID_AB")
ST_BA=$(wait_for_done agent-b "$TID_BA")
if echo "$ST_AB" | grep -qiE "completed|succeeded|done" && echo "$ST_BA" | grep -qiE "completed|succeeded|done"; then
    log_pass "A->B=$ST_AB  B->A=$ST_BA"
else
    log_fail "incomplete: A->B=$ST_AB B->A=$ST_BA"
fi

# ----- 5. Results correlate to the RIGHT processor -----
# A->B task: agent-b processes it, tag "done-by-B:A-to-B"
# B->A task: agent-a processes it, tag "done-by-A:B-to-A"
log_test "each result was processed by the OTHER agent (no self-accept)"
RES1=$($DC exec -T agent-a pilotctl --json task result "$TID_AB" 2>&1 | jq -r '.data.content // empty')
RES2=$($DC exec -T agent-b pilotctl --json task result "$TID_BA" 2>&1 | jq -r '.data.content // empty')
if [ "$RES1" = "done-by-B:A-to-B" ] && [ "$RES2" = "done-by-A:B-to-A" ]; then
    log_pass "A's task was done by B, B's task was done by A"
else
    log_fail "correlation broken (got RES_AB=\"$RES1\" RES_BA=\"$RES2\")"
fi

# ----- 6. No worker accidentally processed its OWN submitted task -----
# The worker log on agent-a must show it accepted B-to-A (its received/), NOT
# A-to-B (which it submitted). Vice versa for agent-b.
log_test "agent-a worker only processed B-to-A, not A-to-B"
WA=$($DC exec -T agent-a cat /tmp/worker.log 2>/dev/null)
if echo "$WA" | grep -q "desc=B-to-A" && ! echo "$WA" | grep -q "desc=A-to-B"; then
    log_pass "agent-a worker touched only its received-side task"
else
    log_fail "agent-a worker log:"
    echo "$WA" | sed 's/^/    /'
fi

log_test "agent-b worker only processed A-to-B, not B-to-A"
WB=$($DC exec -T agent-b cat /tmp/worker.log 2>/dev/null)
if echo "$WB" | grep -q "desc=A-to-B" && ! echo "$WB" | grep -q "desc=B-to-A"; then
    log_pass "agent-b worker touched only its received-side task"
else
    log_fail "agent-b worker log:"
    echo "$WB" | sed 's/^/    /'
fi

# ----- 7. Submitter-side and receiver-side files match up -----
# On each agent, `/root/.pilot/tasks/submitted/` should contain the ID it
# submitted, and `/root/.pilot/tasks/received/` should contain the ID it
# received — crossed, with no overlap.
log_test "per-agent submitted/ and received/ directories are disjoint"
SUB_A=$($DC exec -T agent-a bash -c "ls /root/.pilot/tasks/submitted/ 2>/dev/null")
REC_A=$($DC exec -T agent-a bash -c "ls /root/.pilot/tasks/received/ 2>/dev/null")
SUB_B=$($DC exec -T agent-b bash -c "ls /root/.pilot/tasks/submitted/ 2>/dev/null")
REC_B=$($DC exec -T agent-b bash -c "ls /root/.pilot/tasks/received/ 2>/dev/null")
if echo "$SUB_A" | grep -q "$TID_AB" && echo "$REC_A" | grep -q "$TID_BA" \
   && echo "$SUB_B" | grep -q "$TID_BA" && echo "$REC_B" | grep -q "$TID_AB"; then
    log_pass "file layout is correct on both sides"
else
    log_fail "file layout wrong:"
    echo "  agent-a submitted: $SUB_A"
    echo "  agent-a received:  $REC_A"
    echo "  agent-b submitted: $SUB_B"
    echo "  agent-b received:  $REC_B"
fi

# ----- 8. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup workers
$DC exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Bidirectional tasks test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
