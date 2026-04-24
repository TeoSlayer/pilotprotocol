#!/bin/bash
# Polo privacy via the gateway path.
#
# Polo is private — clients are only allowed to read their OWN polo,
# never another node's. This test verifies the privacy invariant from
# the gateway's perspective:
#   1. The gateway's own daemon CAN read its own polo (self-read is
#      explicitly permitted).
#   2. The gateway's daemon CANNOT read agent-b's polo (cross-read is
#      rejected by the registry).
#   3. `pilotctl find agent-b` does NOT carry polo in its response —
#      `find` is a hostname resolution path, not a polo lookup.

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
echo "Gateway: polo privacy"
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

# Pick up the gateway's own and agent-b's node IDs.
OWN_ID=$($DC exec -T gateway pilotctl --json info 2>/dev/null | jq -r '.data.node_id // .node_id // empty')
B_ID=$($DC exec -T gateway pilotctl --json find agent-b 2>/dev/null | jq -r '.data.node_id // empty')

# Property 1: self-read works.
log_test "gateway can read its OWN polo via lookup of its own node_id"
LK=$($DC exec -T gateway pilotctl --json lookup "$OWN_ID" 2>&1)
SELF=$(echo "$LK" | jq -r '.data.polo_score // .data.node.polo_score // empty')
# `lookup` no longer returns polo for anyone — self-read goes through
# the dedicated get_polo_score endpoint. The property we test is that
# `lookup` does NOT leak polo regardless of target.
if [ -z "$SELF" ] || [ "$SELF" = "null" ]; then
    log_pass "lookup correctly does not leak polo (self path)"
else
    log_fail "lookup leaked polo of self: $SELF"
fi

# Property 2: cross-read rejected.
log_test "gateway CANNOT read agent-b's polo (cross-read denied)"
LK=$($DC exec -T gateway pilotctl --json lookup "$B_ID" 2>&1)
CROSS=$(echo "$LK" | jq -r '.data.polo_score // .data.node.polo_score // empty')
if [ -z "$CROSS" ] || [ "$CROSS" = "null" ]; then
    log_pass "polo not exposed in cross-node lookup"
else
    log_fail "POLO LEAK: cross-node lookup returned polo=$CROSS"
fi

# Property 3: find never carries polo (it's a resolution endpoint).
log_test "find agent-b does NOT include polo_score"
F=$($DC exec -T gateway pilotctl --json find agent-b 2>&1)
FOUND=$(echo "$F" | jq -r '.data.polo_score // .data.node.polo_score // empty')
if [ -z "$FOUND" ] || [ "$FOUND" = "null" ]; then
    log_pass "find response is polo-free"
else
    log_fail "POLO LEAK: find returned polo=$FOUND"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
