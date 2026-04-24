#!/bin/bash
# Register a new node via the gateway's daemon.
#
# FINDING — pilot-gateway does NOT expose a "register a new node" API. The
# only way to register a node is to run pilot-daemon pointed at the registry;
# the daemon performs registration on startup. This test interprets
# "register via gateway" as: the gateway container's own daemon registers
# itself with the rendezvous registry at startup, and that registration is
# observable on the rendezvous dashboard.
#
# EXPECTED: gateway passes through register — shown by the gateway's own
# node appearing in /api/nodes with hostname=gateway.

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
PFX="${PILOT_SUBNET_PREFIX:-172.29.0}"
DASHBOARD="http://${PFX}.10:8080"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Gateway: register (daemon startup registration)"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1

for _ in $(seq 1 90); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 3 ]; then break; fi
    sleep 1
done

log_test "gateway container's own node registered"
GW_NODE=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/nodes 2>/dev/null \
    | jq -r '.nodes[]? | select(.hostname=="gateway") | .node_id // empty' | head -n1)
if [ -n "$GW_NODE" ] && [ "$GW_NODE" != "null" ]; then
    log_pass "gateway node registered (node_id=$GW_NODE)"
else
    log_fail "gateway node not visible in registry"
    $DC exec -T rendezvous curl -s http://127.0.0.1:8080/api/nodes | head -c 500
fi

log_test "gateway-side pilotctl info reports a node_id"
INFO=$($DC exec -T gateway pilotctl --json info 2>&1)
NID=$(echo "$INFO" | jq -r '.data.node_id // empty')
if [ -n "$NID" ] && [ "$NID" != "0" ] && [ "$NID" != "null" ]; then
    log_pass "daemon registered via gateway container (node_id=$NID)"
else
    log_fail "gateway daemon info missing node_id: $(echo "$INFO" | head -c 300)"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
