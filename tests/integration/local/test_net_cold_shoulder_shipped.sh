#!/bin/bash
# Shipped config: configs/networks/cold-shoulder.json
#
# Name's promise: passive-aggressive deny — silently drop traffic from low-score peers
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

CFG="$(pwd)/../../../configs/networks/cold-shoulder.json"
if [ ! -f "$CFG" ]; then
    log_fail "cold-shoulder.json NOT shipped — promise unmet (EXPECTED: passive-aggressive deny — silently drop traffic from low-score peers)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "cold-shoulder-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "negative-score peer datagram denied"
NID_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')

# Policy runner tracks peers only after they generate an event. Drive
# one benign dgram so agent-a's runner creates a peer entry for PEER_B
# (earn rule fires, score +1).
$DC exec -T agent-b pilotctl dgram agent-a 7 --data warmup >/dev/null 2>&1 || true
sleep 1

# Now drive agent-a's view of PEER_B negative so the next dgram trips
# the `ignore` rule (match peer_score < 0 → deny).
$DC exec -T agent-a pilotctl managed score "$NID_B" --net "$NID" --delta -6 >/dev/null 2>&1 || true

$DC exec -T agent-b pilotctl dgram agent-a 7 --data hi >/dev/null 2>&1 || true
sleep 1

if $DC logs agent-a 2>&1 | grep -qiE "datagram rejected: not allowed|datagram\.port_rejected"; then
    log_pass "low-score datagram denied by policy"
else
    log_fail "no datagram deny event in agent-a logs (EXPECTED: cold-shoulder fired)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
