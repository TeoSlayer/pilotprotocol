#!/bin/bash
# Submit a task to agent-b from the gateway container.
#
# FINDING — pilot-gateway is a TCP-bridge; it does NOT expose a task-submit
# HTTP or gRPC API. Task submit goes through pilotctl -> daemon IPC. Tests
# therefore exec into the gateway container and drive pilotctl against the
# gateway-side daemon, which speaks to agent-b's task-submit service (port
# 1003) over the overlay. This covers "task submit via gateway" end-to-end
# from the gateway-side client perspective.
#
# EXPECTED: gateway passes through task-submit — task_id returned, agent-b
# sees the task in its received queue.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.gateway.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Gateway: task submit -> agent-b"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1

for _ in $(seq 1 90); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 3 ]; then break; fi
    sleep 1
done
if [ "${COUNT:-0}" -lt 3 ]; then
    log_fail "stack did not come up ($COUNT nodes)"
    exit 1
fi
log_pass "stack up ($COUNT nodes)"

# Enable tasks on agent-b (receiver side needs to allow inbound submit).
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

log_test "submit task from gateway to agent-b"
OUT=$($DC exec -T gateway pilotctl --json task submit agent-b --task "gw-submit-$(date +%s)" 2>&1)
TID=$(echo "$OUT" | jq -r '.data.task_id // empty' 2>/dev/null)
if [ -n "$TID" ] && [ "$TID" != "null" ]; then
    log_pass "task submitted via gateway (task_id=$TID)"
else
    log_fail "submit failed: $(echo "$OUT" | head -c 300)"
    exit 1
fi

log_test "agent-b sees task in received queue"
SEEN=""
for _ in $(seq 1 20); do
    SEEN=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id==$t) | .task_id')
    if [ -n "$SEEN" ]; then break; fi
    sleep 1
done
if [ -n "$SEEN" ]; then
    log_pass "agent-b received task $SEEN"
else
    log_fail "agent-b never saw task $TID"
fi

# Persist task id for the result test.
mkdir -p results
echo "$TID" > results/gw_last_task.txt

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
