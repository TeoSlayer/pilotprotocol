#!/bin/bash
# Shipped config: configs/networks/sybil-gauntlet.json
#
# Name's promise: anti-sybil — fresh/zero-score peers face strict entry ordeal
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

CFG="$(pwd)/../../configs/networks/sybil-gauntlet.json"
if [ ! -f "$CFG" ]; then
    log_fail "sybil-gauntlet.json NOT shipped — promise unmet (EXPECTED: anti-sybil — fresh/zero-score peers face strict entry ordeal)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "sybil-gauntlet-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "fresh peer with 0 score cannot complete action"
# agent-b is fresh; any privileged action should be denied.
if $DC exec -T agent-b pilotctl send agent-a 1001 --data sybil --timeout 3s >/dev/null 2>&1; then
    log_fail "fresh sybil action succeeded (EXPECTED: denied until gauntlet cleared)"
else
    log_pass "fresh peer gated by sybil gauntlet"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
