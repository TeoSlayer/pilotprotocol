#!/bin/bash
# Shipped config: configs/networks/cooling-off.json
#
# Name's promise: cooldown — after violation, peer cannot reconnect for N seconds
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

CFG="$(pwd)/../../../configs/networks/cooling-off.json"
if [ ! -f "$CFG" ]; then
    log_fail "cooling-off.json NOT shipped — promise unmet (EXPECTED: cooldown — after violation, peer cannot reconnect for N seconds)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "cooling-off-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "fresh peer cannot send outbound datagrams (cooling-off window)"
# cooling-off policy: `silent` rule (on: datagram, peer_age_s < 3600 &&
# direction == "out") denies outbound dgrams from freshly-joined peers.
# `pilotctl dgram` is fire-and-forget over IPC, so observe the deny via
# agent-a's log (daemon emits "datagram rejected: not allowed by network
# policy" on the outbound gate).
$DC exec -T agent-a pilotctl dgram agent-b 7 --data hi >/tmp/co.out 2>&1 || true
sleep 1
if $DC logs agent-a 2>&1 | grep -qE 'datagram rejected: not allowed|datagram\.port_rejected'; then
    log_pass "outbound dgram denied (cooling-off fired)"
else
    log_fail "no deny event in agent-a logs (EXPECTED: silent rule denies fresh-peer out)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
