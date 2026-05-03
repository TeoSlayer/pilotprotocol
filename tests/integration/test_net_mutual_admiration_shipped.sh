#!/bin/bash
# Shipped config: configs/networks/mutual-admiration.json
#
# Name's promise: reciprocal reward — only peers who mutually score each other gain
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

CFG="$(pwd)/../../configs/networks/mutual-admiration.json"
if [ ! -f "$CFG" ]; then
    log_fail "mutual-admiration.json NOT shipped — promise unmet (EXPECTED: reciprocal reward — only peers who mutually score each other gain)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "mutual-admiration-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "unilateral connect produces no score (until mutual)"
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
echo uni | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 3s >/dev/null 2>&1 || true
SC_UNI=$($DC exec -T agent-a pilotctl --json managed score "$NID" "$PEER_B" 2>/dev/null | jq -r ".data.score // 0")
echo back | $DC exec -T agent-b pilotctl connect agent-a 7 --timeout 3s >/dev/null 2>&1 || true
sleep 1
SC_MUTUAL=$($DC exec -T agent-a pilotctl --json managed score "$NID" "$PEER_B" 2>/dev/null | jq -r ".data.score // 0")
if [ "${SC_MUTUAL:-0}" -gt "${SC_UNI:-0}" ]; then
    log_pass "mutual bump: uni=$SC_UNI mutual=$SC_MUTUAL"
else
    log_fail "no mutual bonus: uni=$SC_UNI mutual=$SC_MUTUAL (EXPECTED: increase on reciprocation)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
