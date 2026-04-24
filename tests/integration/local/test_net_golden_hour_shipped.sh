#!/bin/bash
# Shipped config: configs/networks/golden-hour.json
#
# Name's promise: time-window — actions in first N seconds have bonus scoring
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

CFG="$(pwd)/../../../configs/networks/golden-hour.json"
if [ ! -f "$CFG" ]; then
    log_fail "golden-hour.json NOT shipped — promise unmet (EXPECTED: time-window — actions in first N seconds have bonus scoring)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "golden-hour-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "fresh-join datagram accrues newcomer bonus (+5, not +1)"
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
# golden-hour rule order: `newcomer` (peer_age_s < 3600) +5 allow;
# `veteran` (true) +1 allow. Gate-event eval stops at first verdict, so
# fresh peers get +5. Single dgram within the 1h window should land on
# +5 — the +1 veteran path only applies to peers older than an hour.
$DC exec -T agent-a pilotctl dgram agent-b 7 --data gh-fresh >/dev/null 2>&1 || true
sleep 1
SC=$(peer_score agent-a "$NID" "$PEER_B")
if [ "${SC:-0}" -ge 5 ]; then
    log_pass "newcomer bonus fired: score=$SC (>=5)"
else
    log_fail "newcomer bonus missing: score=$SC (EXPECTED: >=5 within 1h of join)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
