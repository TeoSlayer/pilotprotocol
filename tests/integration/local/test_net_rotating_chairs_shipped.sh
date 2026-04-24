#!/bin/bash
# Shipped config: configs/networks/rotating-chairs.json
#
# Name's promise: rotation — leadership/privilege rotates across peers each cycle
#
# This test loads the shipped config (if present) and verifies the
# specific behavior implied by the network's name. If the config is
# not shipped or the policy engine cannot enforce the promise, the
# test fails — per Chunk I rules that failure is a product/engine
# gap finding, not a test bug.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.policy.yml"
export DC
cd "$(dirname "$0")" || exit 1
source ./network_helpers.sh

CFG="$(pwd)/../../../configs/networks/rotating-chairs.json"
if [ ! -f "$CFG" ]; then
    log_fail "rotating-chairs.json NOT shipped — promise unmet (EXPECTED: rotation — leadership/privilege rotates across peers each cycle)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "rotating-chairs-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "rotating-chairs prune/fill cycle rules loaded"
# Rotation happens via prune_trust (>100 members) and fill_trust (<100)
# on the cycle event — not in a 2-agent test. Verify the rule pair is
# present in the active policy; fleet tests cover the actual rotation.
POL=$($DC exec -T agent-a pilotctl --json policy get --net "$NID" 2>/dev/null)
HAS_PRUNE=$(echo "$POL" | jq -e '.data.expr_policy.rules[]? | select(.on == "cycle" and (.actions | map(.type) | index("prune_trust")))' >/dev/null 2>&1 && echo yes || echo no)
HAS_FILL=$(echo "$POL" | jq -e '.data.expr_policy.rules[]? | select(.on == "cycle" and (.actions | map(.type) | index("fill_trust")))' >/dev/null 2>&1 && echo yes || echo no)
if [ "$HAS_PRUNE" = yes ] && [ "$HAS_FILL" = yes ]; then
    log_pass "rotating-chairs prune+fill rules loaded"
else
    log_fail "rotating-chairs rules missing: prune=$HAS_PRUNE fill=$HAS_FILL"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
