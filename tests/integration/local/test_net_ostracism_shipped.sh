#!/bin/bash
# Shipped config: configs/networks/ostracism.json
#
# Current behavior:
#   - cycle: evict_where has_tag(peer_tags, "ostracized")
#   - datagram: log all datagrams (debug)
#
# Assertion: a peer tagged "ostracized" (via member-tags) is evicted on
# the next forced cycle.

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

CFG="$(pwd)/../../../configs/networks/ostracism.json"
if [ ! -f "$CFG" ]; then
    log_fail "ostracism.json NOT shipped"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "ostracism-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")

log_test "ostracized peer is evicted on cycle"
# Tag agent-b as ostracized via member-tags, then force a policy cycle.
$DC exec -T agent-a pilotctl member-tags set --node "$PEER_B" --tags ostracized --net "$NID" >/dev/null 2>&1 || true
$DC exec -T agent-a pilotctl --json managed reconcile --net "$NID" >/dev/null 2>&1 || true
$DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1 || true
sleep 1

# After eviction the peer should no longer appear in managed status peers list.
STATUS=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null)
if echo "$STATUS" | jq -e --argjson p "$PEER_B" '.data.peers[]? | select(.node_id == $p)' >/dev/null 2>&1; then
    log_fail "ostracized peer still present after cycle (EXPECTED: evicted)"
else
    log_pass "ostracized peer evicted on cycle"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
