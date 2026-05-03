#!/bin/bash
# Retrieve task results via the gateway-side daemon.
#
# Builds on test_gateway_task_submit.sh: submits a task from the gateway,
# runs a short worker on agent-b that accepts + returns results, then
# asserts the submitter (gateway) can read the COMPLETED/SUCCEEDED status.
#
# EXPECTED: gateway passes through task-result — status reflects
# COMPLETED/SUCCEEDED and results are non-empty.

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
echo "Gateway: task results round-trip"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1

for _ in $(seq 1 90); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 3 ]; then break; fi
    sleep 1
done
[ "${COUNT:-0}" -lt 3 ] && { log_fail "stack did not come up"; exit 1; }

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Worker loop on agent-b
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "gw-result-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.3
    done
'

log_test "submit task from gateway"
OUT=$($DC exec -T gateway pilotctl --json task submit agent-b --task "gw-result-$(date +%s)" 2>&1)
TID=$(echo "$OUT" | jq -r '.data.task_id // empty')
if [ -z "$TID" ] || [ "$TID" = "null" ]; then
    log_fail "submit failed: $(echo "$OUT" | head -c 300)"
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
    exit 1
fi
log_pass "submitted $TID"

log_test "wait for completion visible to gateway"
STATUS=""
for _ in $(seq 1 30); do
    STATUS=$($DC exec -T gateway pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id==$t) | .status')
    if echo "$STATUS" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done

if echo "$STATUS" | grep -qiE "completed|succeeded|done"; then
    log_pass "gateway-visible status=$STATUS"
else
    log_fail "task never completed (status=$STATUS)"
fi

log_test "gateway reads results payload"
RES=$($DC exec -T gateway pilotctl --json task list --type submitted 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id==$t) | (.results // .result // "")')
if echo "$RES" | grep -q "gw-result-ok"; then
    log_pass "gateway read results: $RES"
else
    log_fail "gateway did not read expected results (got: $RES)"
fi

$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
