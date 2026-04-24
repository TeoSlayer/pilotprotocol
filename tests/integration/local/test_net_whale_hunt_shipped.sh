#!/bin/bash
# Shipped config: configs/networks/whale-hunt.json
#
# Name's promise: big-actor rules — peers above score threshold face extra scrutiny
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

CFG="$(pwd)/../../../configs/networks/whale-hunt.json"
if [ ! -f "$CFG" ]; then
    log_fail "whale-hunt.json NOT shipped — promise unmet (EXPECTED: big-actor rules — peers above score threshold face extra scrutiny)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "whale-hunt-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "whale (>500 score) is harpooned on cycle"
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
# Seed PEER_B's score past the whale threshold (500) and run a cycle;
# `harpoon` rule should evict.
$DC exec -T agent-a pilotctl managed score "$PEER_B" --net "$NID" --delta 600 >/dev/null 2>&1 || true
SC_PRE=$(peer_score agent-a "$NID" "$PEER_B")
$DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1 || true
sleep 1
RANK=$($DC exec -T agent-a pilotctl --json managed rankings --net "$NID" 2>/dev/null)
if [ "${SC_PRE:-0}" -gt 500 ] && ! echo "$RANK" | jq -e --argjson p "$PEER_B" '.data.rankings[]? | select(.node_id == $p)' >/dev/null 2>&1; then
    log_pass "whale harpooned (score $SC_PRE)"
else
    log_fail "whale not evicted (SC_PRE=$SC_PRE, EXPECTED >500 AND peer removed)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
