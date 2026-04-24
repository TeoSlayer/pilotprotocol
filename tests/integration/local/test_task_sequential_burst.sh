#!/bin/bash
# Rapid sequential-burst round-trip: agent-a submits N tasks to agent-b
# back-to-back, agent-b's auto-accept worker processes them one at a time,
# and agent-a's view of task status + result content must show all N
# completed AND in the SAME submission order.
#
# Differs from test_task_executor.sh (single-task round-trip) and from
# test_task_list_ordering.sh (list ordering only, no worker round-trip):
# here we assert that the END-TO-END submit/accept/send-results/result
# cycle preserves FIFO across a burst. Polo is rebalanced via reverse
# flow after each a->b round-trip so the gate doesn't block subsequent
# submits.
#
# Catches:
#  - worker picking tasks in a non-FIFO order mid-burst
#  - result-file writes that race when tasks complete in quick succession
#  - submitter-side status convergence lagging on some tasks but not
#    others (would show up as a partial set of COMPLETED)

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
N=5  # burst size

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Task sequential-burst round-trip ($N tasks)"
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

# ----- 1. Start worker on agent-b: auto-accept + send-results -----
log_test "start auto-accept worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            echo "$(date +%H:%M:%S.%N) accept tid=$TID desc=$DESC" >> /tmp/worker.log
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "result-for-$DESC" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.1
    done
'
sleep 1
log_pass "worker started"

# ----- 2. Start mirror worker on agent-a (for polo rebalancing reverse flow) -----
$DC exec -d agent-a bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "rebal-for-$DESC" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.1
    done
'
sleep 1

# ----- 3. Submit N tasks a->b with polo rebalance between each -----
declare -a TIDS
log_test "submit $N tasks a->b with reverse rebalance after each"
for i in $(seq 1 $N); do
    SUB=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "burst-$i" 2>&1)
    TID=$(echo "$SUB" | jq -r '.data.task_id // empty')
    ACC=$(echo "$SUB" | jq -r '.data.accepted')
    if [ "$ACC" != "true" ] || [ -z "$TID" ]; then
        log_fail "burst-$i submit rejected: $(echo "$SUB" | head -c 250)"
        $DC exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
        $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
        exit 1
    fi
    TIDS[$i]=$TID

    # Wait for a->b completion (so polo reflects it before reverse rebal).
    for _ in $(seq 1 20); do
        ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$ST" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 0.3
    done

    # Reverse b->a to restore polo balance before next iteration.
    RSUB=$($DC exec -T agent-b pilotctl --json task submit agent-a --task "rebal-$i" 2>/dev/null)
    RTID=$(echo "$RSUB" | jq -r '.data.task_id // empty')
    for _ in $(seq 1 20); do
        RST=$($DC exec -T agent-b pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$RTID" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$RST" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 0.3
    done
done
log_pass "$N tasks submitted + rebalanced"

# ----- 4. All N tasks reach COMPLETED on submitter -----
log_test "all $N tasks COMPLETED on agent-a"
OK=0
for i in $(seq 1 $N); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "${TIDS[$i]}" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$ST" | grep -qiE "completed|succeeded|done"; then
        OK=$((OK+1))
    else
        echo "  burst-$i (${TIDS[$i]}) status=$ST" >&2
    fi
done
if [ "$OK" = "$N" ]; then
    log_pass "all $N tasks COMPLETED"
else
    log_fail "only $OK/$N COMPLETED"
fi

# ----- 5. Each result has the correct correlated content -----
log_test "each result correlates to its burst-i description"
CORR=0
for i in $(seq 1 $N); do
    CONTENT=$($DC exec -T agent-a pilotctl --json task result "${TIDS[$i]}" 2>/dev/null | jq -r '.data.content // empty')
    if [ "$CONTENT" = "result-for-burst-$i" ]; then
        CORR=$((CORR+1))
    else
        echo "  burst-$i: expected \"result-for-burst-$i\", got \"$CONTENT\"" >&2
    fi
done
if [ "$CORR" = "$N" ]; then
    log_pass "all $N results correlate"
else
    log_fail "only $CORR/$N results correlated"
fi

# ----- 6. task list --type submitted is ordered: burst-1 first, burst-N last -----
log_test "submitted list preserves burst order"
LIST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
# Pull only burst-* tasks, in the order the daemon returns them.
BURSTS=$(echo "$LIST" | jq -r '.data.tasks[] | select(.description | startswith("burst-")) | .description')
EXPECTED=$(for i in $(seq 1 $N); do echo "burst-$i"; done)
if [ "$BURSTS" = "$EXPECTED" ]; then
    log_pass "submitted list is in burst-1..burst-$N order"
else
    log_fail "submitted list out of order"
    echo "  expected:"; echo "$EXPECTED" | sed 's/^/    /'
    echo "  got:";      echo "$BURSTS"   | sed 's/^/    /'
fi

# ----- 7. Worker accept-order log matches submission order -----
log_test "worker accept log shows burst-1..burst-$N in submission order"
ACCEPTS=$($DC exec -T agent-b bash -c "grep -oE 'desc=burst-[0-9]+' /tmp/worker.log 2>/dev/null" | sed 's/^desc=//')
EXP_ACC=$(for i in $(seq 1 $N); do echo "burst-$i"; done)
if [ "$ACCEPTS" = "$EXP_ACC" ]; then
    log_pass "worker accepted in submission order"
else
    log_fail "worker accept order diverges from submission order"
    echo "  expected:"; echo "$EXP_ACC"  | sed 's/^/    /'
    echo "  got:";      echo "$ACCEPTS" | sed 's/^/    /'
fi

# ----- 8. No panic/fatal in daemon logs -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup
$DC exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Sequential-burst test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
