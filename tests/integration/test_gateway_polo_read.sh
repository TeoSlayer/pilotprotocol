#!/bin/bash
# Read polo score via the gateway-side daemon.
#
# EXPECTED: gateway passes through polo read — a non-negative score is
# returned for the gateway's own node.

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
echo "Gateway: polo read"
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

log_test "read own polo score via gateway (real CLI: pilotctl info, and lookup of own id)"
# There is no `pilotctl polo` subcommand. Real path: `info` for own identity, then
# `lookup <node_id>` → .data.polo_score (registry source of truth).
OUT=$($DC exec -T gateway pilotctl --json info 2>&1)
OWN_ID=$(echo "$OUT" | jq -r '.data.node_id // .node_id // empty')
SCORE=$(echo "$OUT" | jq -r '.data.polo_score // .data.polo // empty' 2>/dev/null)
if [ -z "$SCORE" ] || [ "$SCORE" = "null" ]; then
    if [ -n "$OWN_ID" ]; then
        LK=$($DC exec -T gateway pilotctl --json lookup "$OWN_ID" 2>&1)
        SCORE=$(echo "$LK" | jq -r '.data.polo_score // .data.node.polo_score // empty' 2>/dev/null)
    fi
fi

if [ -n "$SCORE" ] && [ "$SCORE" != "null" ]; then
    log_pass "gateway polo score readable: $SCORE"
else
    log_fail "no polo score available via gateway-side pilotctl: $(echo "$OUT" | head -c 300)"
fi

log_test "read agent-b's polo via gateway (lookup agent-b)"
OUT=$($DC exec -T gateway pilotctl --json lookup agent-b 2>&1)
SCORE_B=$(echo "$OUT" | jq -r '.data.polo_score // .data.node.polo_score // empty' 2>/dev/null)
if [ -n "$SCORE_B" ] && [ "$SCORE_B" != "null" ]; then
    log_pass "gateway read agent-b polo: $SCORE_B"
else
    log_fail "polo of agent-b not present in lookup result: $(echo "$OUT" | head -c 300)"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
