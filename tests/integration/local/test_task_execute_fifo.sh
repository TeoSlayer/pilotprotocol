#!/bin/bash
# Task-execute FIFO ordering: when multiple tasks are ACCEPTED, calling
# `pilotctl task execute` repeatedly should pull them in submission order
# (FIFO), not directory-iteration order (alphabetical by UUID).
#
# The daemon keeps an in-memory TaskQueue that tracks insertion order,
# but cmdTaskExecute scans the ~/.pilot/tasks/received directory and
# picks the first match — which on most filesystems is alphabetical by
# filename. Task IDs are v4 UUIDs with no time prefix, so alphabetical
# order is effectively random relative to submission order. This test
# submits 3 tasks back-to-back and asserts FIFO execute order.
#
# Failure is the expected outcome if the bug exists — we then sort by
# created_at to fix.

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
echo "Task execute FIFO ordering integration"
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

# ----- 1. Submit 3 tasks back-to-back, recording order -----
log_test "submit T1, T2, T3 in order"
declare -a TIDS
for i in 1 2 3; do
    SUB=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "fifo-$i" 2>&1)
    TID=$(echo "$SUB" | jq -r '.data.task_id // empty')
    if [ -z "$TID" ]; then
        log_fail "submit T$i failed: $(echo "$SUB" | head -c 200)"
        exit 1
    fi
    TIDS[$i]=$TID
    sleep 0.3  # ensure distinct created_at timestamps
done
log_pass "T1=${TIDS[1]:0:8}... T2=${TIDS[2]:0:8}... T3=${TIDS[3]:0:8}..."

# ----- 2. Accept all 3 in submission order -----
log_test "accept all 3 in submission order"
for i in 1 2 3; do
    ACC=$($DC exec -T agent-b pilotctl --json task accept --id "${TIDS[$i]}" 2>&1)
    if ! echo "$ACC" | jq -e '.data.status == "ACCEPTED"' >/dev/null 2>&1; then
        log_fail "accept T$i failed: $(echo "$ACC" | head -c 200)"
        exit 1
    fi
done
log_pass "all 3 ACCEPTED"

# ----- 3. Execute each in turn; collect order -----
log_test "task execute returns tasks in FIFO submission order"
declare -a EXEC_ORDER
for i in 1 2 3; do
    EX=$($DC exec -T agent-b pilotctl --json task execute 2>&1)
    EX_TID=$(echo "$EX" | jq -r '.data.task_id // empty')
    if [ -z "$EX_TID" ]; then
        log_fail "execute #$i returned no task: $(echo "$EX" | head -c 200)"
        exit 1
    fi
    EXEC_ORDER[$i]=$EX_TID
    # Complete the task so the next execute picks a new ACCEPTED one.
    $DC exec -T agent-b pilotctl task send-results --id "$EX_TID" --results "done-$i" >/dev/null 2>&1
done

MISMATCHES=0
for i in 1 2 3; do
    if [ "${EXEC_ORDER[$i]}" != "${TIDS[$i]}" ]; then
        MISMATCHES=$((MISMATCHES+1))
    fi
done
if [ "$MISMATCHES" -eq 0 ]; then
    log_pass "FIFO preserved: T1 -> T2 -> T3"
else
    log_fail "FIFO violated ($MISMATCHES/3 mismatches)"
    for i in 1 2 3; do
        mark="ok"
        [ "${EXEC_ORDER[$i]}" != "${TIDS[$i]}" ] && mark="WRONG"
        echo "  slot $i: submitted=${TIDS[$i]:0:8} executed=${EXEC_ORDER[$i]:0:8}  [$mark]"
    done
fi

# ----- 4. Queue empty after draining -----
log_test "task queue empty after draining"
Q=$($DC exec -T agent-b pilotctl --json task queue 2>&1)
Q_LEN=$(echo "$Q" | jq -r '.data.queue | length // 0')
if [ "$Q_LEN" = "0" ]; then
    log_pass "queue drained"
else
    log_fail "queue not empty: $Q_LEN tasks remain"
fi

# ----- 5. No panics/fatals -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Task execute FIFO test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
