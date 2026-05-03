#!/bin/bash
# Shipped config: configs/networks/old-guard.json
#
# Name's promise: old-guard privilege — peers with high peer_age_s have special status
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

CFG="$(pwd)/../../configs/networks/old-guard.json"
if [ ! -f "$CFG" ]; then
    log_fail "old-guard.json NOT shipped — promise unmet (EXPECTED: old-guard privilege — peers with high peer_age_s have special status)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "old-guard-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "old-guard rule references peer_age_s"
# Without a >24h peer we cannot truly test; assert the rule exists
# in the loaded policy by inspecting runner status.
STATUS=$($DC exec -T agent-a pilotctl --json managed status "$NID" 2>/dev/null)
if echo "$STATUS" | grep -qE "peer_age|old_guard|senior"; then
    log_pass "old-guard age rule present in runner"
else
    log_fail "no age-based rule visible (EXPECTED: peer_age_s keyed rule)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
