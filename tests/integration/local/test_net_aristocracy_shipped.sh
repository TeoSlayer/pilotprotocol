#!/bin/bash
# Shipped config: configs/networks/aristocracy.json
#
# Name's promise: elite-member privileges — peers with tag 'elite' have elevated access
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

CFG="$(pwd)/../../../configs/networks/aristocracy.json"
if [ ! -f "$CFG" ]; then
    log_fail "aristocracy.json NOT shipped — promise unmet (EXPECTED: elite-member privileges — peers with tag 'elite' have elevated access)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "aristocracy-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")

log_test "noble (score>=50) can dial; plebian is denied"
# Policy: `noble-only` allows dial when peer_score>=50; `plebian-deny`
# catches all other dials with deny. Seed agent-a's view of PEER_B to
# noble level then dial; confirm it goes through.
$DC exec -T agent-a pilotctl managed score "$PEER_B" --net "$NID" --delta 60 >/dev/null 2>&1 || true
if echo hi | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 5s >/dev/null 2>&1; then
    log_pass "noble dial allowed (score>=50)"
else
    log_fail "noble dial denied (EXPECTED: noble-only rule)"
fi

log_test "plebian (score<50) dial is denied"
# Drop score back below the threshold and dial again — plebian-deny
# should close the door.
$DC exec -T agent-a pilotctl managed score "$PEER_B" --net "$NID" --delta -60 >/dev/null 2>&1 || true
if echo hi | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 3s >/dev/null 2>&1; then
    log_fail "plebian dial succeeded (EXPECTED: deny)"
else
    log_pass "plebian dial denied (asymmetric privilege confirmed)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
