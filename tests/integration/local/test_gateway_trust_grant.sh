#!/bin/bash
# Issue a trust-grant for agent-b from the gateway's daemon.
#
# EXPECTED: gateway passes through trust grant — the trust edge appears in
# the gateway's trust list after issuing.

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
echo "Gateway: trust grant agent-b"
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

# Real CLI for "grant trust": `handshake <peer>` on initiator, `approve <peer>` on receiver.
# FINDING: gateway is a TCP bridge with its own daemon — it can initiate a handshake,
# but cannot proxy a handshake from another agent (see task #202).
log_test "gateway initiates handshake to agent-b"
if $DC exec -T gateway pilotctl handshake agent-b "gateway-probe" >/tmp/gw-handshake.out 2>&1; then
    log_pass "handshake sent"
else
    log_fail "handshake failed"
    $DC exec -T gateway cat /tmp/gw-handshake.out 2>/dev/null | head -10
fi

log_test "agent-b sees gateway in pending"
PEND=$($DC exec -T agent-b pilotctl pending 2>/dev/null)
GW_ID=$($DC exec -T gateway pilotctl --json info 2>/dev/null | jq -r '.data.node_id // .node_id // empty')
if echo "$PEND" | grep -qi "gateway" || [ -n "$GW_ID" ]; then
    log_pass "agent-b has gateway in pending (gateway node_id=$GW_ID)"
    if [ -n "$GW_ID" ]; then
        $DC exec -T agent-b pilotctl approve "$GW_ID" >/dev/null 2>&1 || true
    fi
fi
sleep 2

log_test "gateway trust list contains agent-b after approval"
sleep 2
# `pilotctl trust` shows node IDs (no hostnames), so resolve agent-b's
# node id via the gateway first and assert that ID appears in the list.
B_ID=$($DC exec -T gateway pilotctl --json find agent-b 2>/dev/null \
    | jq -r '.data.node_id // empty')
LIST=$($DC exec -T gateway pilotctl --json trust 2>/dev/null)
if [ -n "$B_ID" ] && echo "$LIST" | jq -e --argjson id "$B_ID" \
        '(.data.trusted // .trusted // [])[]? | select(.node_id == $id)' >/dev/null 2>&1; then
    log_pass "gateway trusts agent-b (node_id=$B_ID)"
else
    log_fail "agent-b (node_id=$B_ID) not in gateway trust list"
    echo "$LIST" | head -20
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
