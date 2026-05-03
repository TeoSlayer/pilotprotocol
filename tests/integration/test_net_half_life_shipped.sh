#!/bin/bash
# Shipped config: configs/networks/half-life.json
#
# Name's promise: exponential decay — scores halve each cycle
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

CFG="$(pwd)/../../configs/networks/half-life.json"
if [ ! -f "$CFG" ]; then
    log_fail "half-life.json NOT shipped — promise unmet (EXPECTED: exponential decay — scores halve each cycle)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "half-life-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
for i in $(seq 1 8); do
    echo h-$i | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 2s >/dev/null 2>&1 || true
done
sleep 1
S0=$($DC exec -T agent-a pilotctl --json managed score "$NID" "$PEER_B" 2>/dev/null | jq -r ".data.score // 0")
$DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1
S1=$($DC exec -T agent-a pilotctl --json managed score "$NID" "$PEER_B" 2>/dev/null | jq -r ".data.score // 0")
# Accept "S1 <= S0/2 + tolerance" as half-life.
THRESH=$(( (S0 + 1) / 2 + 1 ))
if [ "${S1:-0}" -le "$THRESH" ]; then
    log_pass "half-life decay: $S0 -> $S1 (<= $THRESH)"
else
    log_fail "decay too weak: $S0 -> $S1 (EXPECTED: ~half)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
