#!/bin/bash
# Shipped config: configs/networks/burnout.json
#
# Name's promise: activity-cap — peer above activity threshold is throttled/evicted
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

CFG="$(pwd)/../../../configs/networks/burnout.json"
if [ ! -f "$CFG" ]; then
    log_fail "burnout.json NOT shipped — promise unmet (EXPECTED: activity-cap — peer above activity threshold is throttled/evicted)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "burnout-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "generate burst traffic to trigger burnout cap"
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
SC0=$(peer_score agent-a "$NID" "$PEER_B")
# burnout `earn` rule is on: datagram (any direction). Burst dgrams from
# agent-a → agent-b; agent-a's local view of PEER_B ticks per event,
# then force a cycle to let fatigue/retire rules fire.
for i in $(seq 1 20); do
    $DC exec -T agent-a pilotctl dgram agent-b 7 --data "burn-$i" >/dev/null 2>&1 || true
done
sleep 2
$DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1 || true

SC=$(peer_score agent-a "$NID" "$PEER_B")
RANK=$($DC exec -T agent-a pilotctl --json managed rankings --net "$NID" 2>/dev/null)
LISTED=$(echo "$RANK" | grep -c "$PEER_B")

log_test "after burst, score is bounded or peer evicted (burnout cap)"
# Strengthened: require proof the engine observed activity (score changed or
# peer was evicted). Pure zero-scored, still-listed peer = silent no-op, not
# a burnout cap. Accept either: (a) score grew then was capped below a
# per-event-sum ceiling, OR (b) peer is no longer in rankings after burst.
MOVED=0
if [ "${SC:-0}" -ne "${SC0:-0}" ] || [ "$LISTED" -eq 0 ]; then
    MOVED=1
fi
if [ "$MOVED" -eq 1 ] && { [ "${SC:-0}" -lt 20 ] || [ "$LISTED" -eq 0 ]; }; then
    log_pass "burnout cap applied (score=$SC0->$SC, listed=$LISTED)"
else
    log_fail "no burnout cap observed: score=$SC0->$SC listed=$LISTED (EXPECTED: score moved AND bounded, OR peer evicted)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
