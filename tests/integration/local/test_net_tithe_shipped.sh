#!/bin/bash
# Shipped config: configs/networks/tithe.json
#
# Name's promise: compulsory contribution — every N events, score is clipped
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

CFG="$(pwd)/../../../configs/networks/tithe.json"
if [ ! -f "$CFG" ]; then
    log_fail "tithe.json NOT shipped — promise unmet (EXPECTED: compulsory contribution — every N events, score is clipped)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "tithe-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "tithe clips accumulated score on cycle"
PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
# tithe: `earn` +2/connect fires on receiver (agent-b) scoring PEER_A;
# `tithe` -5 on cycle; `evict` removes peer_score < 0 on cycle. We need
# a positive buffer before the cycle, else tithe drops into negative
# and evict removes the peer. Seed via 10 connects (+20 on agent-b's
# view of PEER_A). The next cycle's tithe deducts 5 → 15.
for i in $(seq 1 10); do
    echo t-$i | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 2s >/dev/null 2>&1 || true
done
sleep 1
# Seed more buffer in case the prior sync_policy_peers cycle already
# dropped PEER_A to negative and evicted it. `managed score` only
# succeeds if peer is tracked — the 10 connects guarantee that.
$DC exec -T agent-b pilotctl managed score "$PEER_A" --net "$NID" --delta 20 >/dev/null 2>&1 || true
SC_PRE=$(peer_score agent-b "$NID" "$PEER_A")
$DC exec -T agent-b pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1
SC_POST=$(peer_score agent-b "$NID" "$PEER_A")
if [ -n "$SC_POST" ] && [ "${SC_POST:-0}" -lt "${SC_PRE:-0}" ]; then
    log_pass "tithe clipped: $SC_PRE -> $SC_POST"
else
    log_fail "no tithe: $SC_PRE -> $SC_POST (EXPECTED: score decrease)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
