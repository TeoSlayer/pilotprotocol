#!/bin/bash
# Resolve agent-b address via the gateway's daemon (registry lookup).

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
echo "Gateway: lookup agent-b"
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
    log_fail "only $COUNT nodes registered"
    exit 1
fi
log_pass "stack up (total_nodes=$COUNT)"

log_test "pilotctl find agent-b via gateway daemon"
# `pilotctl lookup` takes a numeric node_id; use `find` to resolve by hostname.
LK=$($DC exec -T gateway pilotctl --json find agent-b 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty' 2>/dev/null)
if [ -n "$ADDR" ] && [ "$ADDR" != "null" ]; then
    log_pass "gateway-side find resolved agent-b: $ADDR"
else
    log_fail "find failed: $(echo "$LK" | head -c 300)"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
