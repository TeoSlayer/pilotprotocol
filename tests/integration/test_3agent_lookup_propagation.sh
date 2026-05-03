#!/bin/bash
# Lookup propagation: bring up rendezvous + agent-a + agent-b first, then
# later start agent-c. Verify that agent-a (and agent-b) can lookup
# agent-c within a bounded time after c registers.
#
# Finds bugs where:
#   - rendezvous caches stale "not found" for a name that later appears
#   - clients cache negative results too aggressively
#   - register→visible delay is large

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

DC="docker compose -f docker-compose.multi3.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "3-agent lookup propagation"
echo "=========================================="

log_test "bring up rendezvous + agent-a + agent-b only"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
if COUNT=$(wait_all_registered 2 rendezvous); then
    log_pass "a+b registered (total=$COUNT)"
else
    log_fail "a+b failed to register (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

# Pre-heat a negative lookup for agent-c from agent-a BEFORE c registers.
log_test "agent-a lookup of agent-c currently fails (c not up)"
LK=$($DC exec -T agent-a pilotctl --json lookup agent-c 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -z "$ADDR" ] || [ "$ADDR" = "null" ]; then
    log_pass "agent-a correctly fails to resolve agent-c (pre-register)"
else
    log_fail "agent-a unexpectedly resolved agent-c to $ADDR"
fi

# Now bring up agent-c.
log_test "bring up agent-c"
$DC up -d agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "total=$COUNT (agent-c registered)"
else
    log_fail "agent-c never registered (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

# Propagation: agent-a lookup should succeed soon.
log_test "agent-a can lookup agent-c within 15s of registration"
ADDR_A=""
for _ in $(seq 1 15); do
    ADDR_A=$($DC exec -T agent-a pilotctl --json lookup agent-c 2>/dev/null | jq -r '.data.address // empty')
    if [ -n "$ADDR_A" ] && [ "$ADDR_A" != "null" ]; then break; fi
    sleep 1
done
if [ -n "$ADDR_A" ] && [ "$ADDR_A" != "null" ]; then
    log_pass "agent-a sees agent-c: $ADDR_A"
else
    log_fail "agent-a still cannot see agent-c after 15s (negative cache?)"
fi

log_test "agent-b can lookup agent-c within 15s"
ADDR_B=""
for _ in $(seq 1 15); do
    ADDR_B=$($DC exec -T agent-b pilotctl --json lookup agent-c 2>/dev/null | jq -r '.data.address // empty')
    if [ -n "$ADDR_B" ] && [ "$ADDR_B" != "null" ]; then break; fi
    sleep 1
done
if [ -n "$ADDR_B" ] && [ "$ADDR_B" != "null" ]; then
    log_pass "agent-b sees agent-c: $ADDR_B"
else
    log_fail "agent-b still cannot see agent-c after 15s"
fi

log_test "both views of agent-c address agree"
if [ "$ADDR_A" = "$ADDR_B" ] && [ -n "$ADDR_A" ]; then
    log_pass "addresses match across agents"
else
    log_fail "addresses disagree: a=$ADDR_A b=$ADDR_B"
fi

log_test "agent-c can ping back to agent-a and agent-b"
if $DC exec -T agent-c pilotctl ping agent-a --count 1 --timeout 10s >/dev/null 2>&1; then
    log_pass "c->a ping ok"
else
    log_fail "c->a ping failed"
fi
if $DC exec -T agent-c pilotctl ping agent-b --count 1 --timeout 10s >/dev/null 2>&1; then
    log_pass "c->b ping ok"
else
    log_fail "c->b ping failed"
fi

log_test "no panic/fatal"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "3-agent lookup propagation summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
