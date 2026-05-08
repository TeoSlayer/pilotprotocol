#!/bin/bash
# Shipped config: configs/networks/cold-shoulder.json
#
# Current behavior:
#   - cycle: fill_trust target=0 (every 12h cycle clears all trusted peers)
#
# Assertion: after a forced cycle, the managed peer count drops to 0
# (all trust cleared by fill_trust target=0).

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
    log_fail "cold-shoulder.json NOT shipped"
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

log_test "peers tracked before cycle"
STATUS_PRE=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null)
COUNT_PRE=$(echo "$STATUS_PRE" | jq '.data.peer_count // 0')
if [ "${COUNT_PRE:-0}" -gt 0 ]; then
    log_pass "pre-cycle peer_count=$COUNT_PRE"
else
    log_fail "no peers tracked before cycle (count=$COUNT_PRE)"
fi

log_test "cycle clears all peers (fill_trust target=0)"
$DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1 || true
sleep 1
STATUS_POST=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null)
COUNT_POST=$(echo "$STATUS_POST" | jq '.data.peer_count // -1')
if [ "${COUNT_POST:-1}" -eq 0 ]; then
    log_pass "post-cycle peer_count=0 (cold shoulder applied)"
else
    log_fail "post-cycle peer_count=$COUNT_POST (EXPECTED: 0 — fill_trust target=0 should clear all)"
fi

# Update the stale description
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
