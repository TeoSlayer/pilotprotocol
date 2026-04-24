#!/bin/bash
# Task list / queue display ordering: both `pilotctl task list` and
# `pilotctl task queue` should return tasks in FIFO (submission time)
# order, not directory-iteration order. Task IDs are v4 UUIDs with no
# time prefix, so alphabetical directory iteration produces random
# display order — bad for any user or worker scanning the list.
#
# Pairs with test_task_execute_fifo.sh (which covers the selector) — this
# one covers the read-only listings.

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
echo "Task list/queue ordering integration"
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

# ----- Submit 4 tasks, spaced to keep created_at distinct -----
log_test "submit T1..T4"
declare -a TIDS
for i in 1 2 3 4; do
    SUB=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "order-$i" 2>&1)
    TID=$(echo "$SUB" | jq -r '.data.task_id // empty')
    if [ -z "$TID" ]; then
        log_fail "submit T$i: $(echo "$SUB" | head -c 200)"
        exit 1
    fi
    TIDS[$i]=$TID
    sleep 0.25
done
log_pass "4 tasks submitted"

# ----- `task list --type submitted` on a must show T1..T4 in FIFO order -----
log_test "task list --type submitted is ordered by created_at ascending"
LIST_A=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
ORDER_A=$(echo "$LIST_A" | jq -r '.data.tasks[].task_id' | tr '\n' ' ')
EXPECTED="${TIDS[1]} ${TIDS[2]} ${TIDS[3]} ${TIDS[4]} "
if [ "$ORDER_A" = "$EXPECTED" ]; then
    log_pass "submitter list is FIFO"
else
    log_fail "submitter list out of order"
    echo "  expected: $EXPECTED"
    echo "  got:      $ORDER_A"
fi

# ----- `task list --type received` on b must also be FIFO -----
log_test "task list --type received is ordered by created_at ascending"
LIST_B=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null)
ORDER_B=$(echo "$LIST_B" | jq -r '.data.tasks[].task_id' | tr '\n' ' ')
if [ "$ORDER_B" = "$EXPECTED" ]; then
    log_pass "receiver list is FIFO"
else
    log_fail "receiver list out of order"
    echo "  expected: $EXPECTED"
    echo "  got:      $ORDER_B"
fi

# ----- Accept all; `task queue` must be FIFO -----
log_test "accept all 4 and task queue is ordered FIFO"
for i in 1 2 3 4; do
    $DC exec -T agent-b pilotctl --json task accept --id "${TIDS[$i]}" >/dev/null 2>&1
done
Q=$($DC exec -T agent-b pilotctl --json task queue 2>/dev/null)
ORDER_Q=$(echo "$Q" | jq -r '.data.queue[].task_id' | tr '\n' ' ')
if [ "$ORDER_Q" = "$EXPECTED" ]; then
    log_pass "queue is FIFO"
else
    log_fail "queue out of order"
    echo "  expected: $EXPECTED"
    echo "  got:      $ORDER_Q"
fi

# ----- `task list` (no filter) must ALSO return deterministic ordering -----
# With both received and submitted populated we at least check that
# tasks within each category are FIFO; the category-join order is
# up to the implementation.
log_test "unfiltered task list groups each category in FIFO"
LIST_ALL=$($DC exec -T agent-a pilotctl --json task list 2>/dev/null)
SUB_SIDE=$(echo "$LIST_ALL" | jq -r '.data.tasks[] | select(.category == "submitted") | .task_id' | tr '\n' ' ')
if [ "$SUB_SIDE" = "$EXPECTED" ]; then
    log_pass "unfiltered list preserves FIFO within submitted category"
else
    log_fail "unfiltered list out of order within submitted"
    echo "  expected: $EXPECTED"
    echo "  got:      $SUB_SIDE"
fi

# ----- No panics/fatals -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Task list/queue ordering test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
