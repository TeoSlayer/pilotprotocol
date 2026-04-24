#!/bin/bash
# Shipped config: configs/networks/gossip-tax.json
#
# Name's promise: reputation tax — peers emitting too many pubsub events lose score
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

CFG="$(pwd)/../../../configs/networks/gossip-tax.json"
if [ ! -f "$CFG" ]; then
    log_fail "gossip-tax.json NOT shipped — promise unmet (EXPECTED: reputation tax — peers emitting too many pubsub events lose score)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "gossip-tax-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "excessive outbound datagrams drain sender's view of destination"
PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
# gossip-tax `speak` rule (on: datagram, direction==out) scores -K on
# the destination peer in the sender's runner. Seed agent-b's view of
# PEER_A positive first so the drain is measurable, then have agent-b
# blast outbound dgrams to agent-a and verify its view drops.
$DC exec -T agent-b pilotctl managed score "$PEER_A" --net "$NID" --delta 10 >/dev/null 2>&1 || true
SC0=$(peer_score agent-b "$NID" "$PEER_A")
for i in $(seq 1 15); do
    $DC exec -T agent-b pilotctl dgram agent-a 7 --data "gossip-$i" >/dev/null 2>&1 || true
done
sleep 1
SC1=$(peer_score agent-b "$NID" "$PEER_A")
if [ "${SC0:-0}" -gt 0 ] && [ "${SC1:-0}" -lt "${SC0:-0}" ]; then
    log_pass "gossip tax applied: $SC0 -> $SC1"
else
    log_fail "no gossip tax: $SC0 -> $SC1 (EXPECTED: SC0>0 AND SC1<SC0 after outbound storm)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
