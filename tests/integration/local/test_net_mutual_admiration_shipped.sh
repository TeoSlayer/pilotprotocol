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

CFG="$(pwd)/../../../configs/networks/mutual-admiration.json"
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
sync_policy_peers "$NID" agent-a agent-b

log_test "strangers denied, members (score>=5) gain on connect"
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")

# `on: connect` fires on the RECEIVING side — agent-b evaluates its
# view of PEER_A when agent-a dials. Stranger phase: agent-b's view of
# PEER_A is 0, handshake fails (needs >=5), stranger denies.
echo uni | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 3s >/dev/null 2>&1 || true
SC_STRANGER=$(peer_score agent-b "$NID" "$PEER_A")

# Admit PEER_A into the society by seeding agent-b's view of it to 5.
# Next connect will pass handshake (5>=5), score +1, allow → score=6.
$DC exec -T agent-b pilotctl managed score "$PEER_A" --net "$NID" --delta 5 >/dev/null 2>&1 || true
echo member | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 3s >/dev/null 2>&1 || true
sleep 1
SC_MEMBER=$(peer_score agent-b "$NID" "$PEER_A")

if [ "${SC_STRANGER:-0}" -eq 0 ] && [ "${SC_MEMBER:-0}" -gt 5 ]; then
    log_pass "gate enforced: stranger=$SC_STRANGER member=$SC_MEMBER"
else
    log_fail "gate broken: stranger=$SC_STRANGER member=$SC_MEMBER (EXPECTED: stranger=0, member>5)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
