#!/bin/bash
# Shipped config: configs/networks/high-trust-society.json
#
# Current rules:
#   trust-decay (cycle): prune_trust when trusted_count > 100
#   trust-fill  (cycle): fill_trust  when trusted_count < 100
#   score-connections (connect): allow
#   score-datagrams   (datagram): allow
#
# Assertions:
#   1. Policy loads without error.
#   2. Both agents can communicate (ping succeeds) — allow rules permit traffic.

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

CFG="$(pwd)/../../../configs/networks/high-trust-society.json"
[ -f "$CFG" ] || { log_fail "missing $CFG"; exit 1; }

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "hts-$$" "1m") || { log_fail "create network"; exit 1; }
log_pass "net=$NID"

start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "policy loaded — runner visible in managed status"
STATUS=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null)
if echo "$STATUS" | jq -e '.data' >/dev/null 2>&1; then
    log_pass "policy runner active on agent-a"
else
    log_fail "managed status returned no data: $STATUS"
fi

log_test "ping agent-a -> agent-b (score-connections allow rule)"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 8s >/dev/null 2>&1; then
    log_pass "ping succeeded — allow rules permit traffic"
else
    log_fail "ping failed — allow rules not working"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
