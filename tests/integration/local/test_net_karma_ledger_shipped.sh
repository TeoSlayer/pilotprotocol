#!/bin/bash
# Shipped config: configs/networks/karma-ledger.json
#
# Name's promise: persistent karma — every action updates a signed running total
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

CFG="$(pwd)/../../../configs/networks/karma-ledger.json"
if [ ! -f "$CFG" ]; then
    log_fail "karma-ledger.json NOT shipped — promise unmet (EXPECTED: persistent karma — every action updates a signed running total)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "karma-ledger-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
log_test "3 datagrams update karma ledger"
# karma-ledger policy: receive-tip (+2 on inbound dgram), send-tax (-1 on
# outbound). Read agent-b's view of agent-a BEFORE and AFTER; each
# inbound dgram from agent-a should tick agent-b's view of PEER_A by +2.
SC0=$(peer_score agent-b "$NID" "$PEER_A")
for i in 1 2 3; do
    $DC exec -T agent-a pilotctl dgram agent-b 7 --data "k-$i" >/dev/null 2>&1 || true
done
sleep 2
SC1=$(peer_score agent-b "$NID" "$PEER_A")
if [ "${SC1:-0}" -gt "${SC0:-0}" ]; then
    log_pass "karma ticked: $SC0 -> $SC1"
else
    log_fail "karma did not change (EXPECTED: monotonic increase)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
