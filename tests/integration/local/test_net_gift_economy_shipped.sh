#!/bin/bash
# Shipped config: configs/networks/gift-economy.json
#
# Name's promise: gift-economy — asymmetric reward (sender gets +, receiver +)
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

CFG="$(pwd)/../../../configs/networks/gift-economy.json"
if [ ! -f "$CFG" ]; then
    log_fail "gift-economy.json NOT shipped — promise unmet (EXPECTED: gift-economy — asymmetric reward (sender gets +, receiver +))"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "gift-economy-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
# gift-economy: `receive` rule (direction==in) scores sender +1.
# Bidirectional dgrams so each side sees its peer accrue reward.
$DC exec -T agent-a pilotctl dgram agent-b 7 --data gift-a2b >/dev/null 2>&1 || true
$DC exec -T agent-b pilotctl dgram agent-a 7 --data gift-b2a >/dev/null 2>&1 || true
sleep 1
SC_B=$(peer_score agent-a "$NID" "$PEER_B")  # a's view of b after b sent to a
SC_A=$(peer_score agent-b "$NID" "$PEER_A")  # b's view of a after a sent to b
log_test "both sender and receiver accrue reward"
if [ "${SC_A:-0}" -gt 0 ] && [ "${SC_B:-0}" -gt 0 ]; then
    log_pass "gift-economy: a->b score=$SC_A  b->a score=$SC_B"
else
    log_fail "asymmetric rewards missing: A=$SC_A B=$SC_B (EXPECTED: both >0)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
