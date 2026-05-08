#!/bin/bash
# Shipped config: configs/networks/high-trust-society.json
#
# Current behavior:
#   - cycle: prune_trust when trusted_count > 100 (10%, min 100)
#   - cycle: fill_trust when trusted_count < 100 (target 100)
#   - connect/datagram: allow all traffic

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

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

CFG="$(pwd)/../../../configs/networks/high-trust-society.json"
[ -f "$CFG" ] || { log_fail "missing $CFG"; exit 1; }

NID=$(create_network_from_file "$CFG" "hts-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"

start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "policy runner loads and traffic is allowed"
if $DC exec -T agent-a pilotctl --json managed status --net "$NID" >/dev/null 2>&1; then
    log_pass "managed status ok"
else
    log_fail "managed status failed"
fi

log_test "ping succeeds (allow rules permit all traffic)"
if $DC exec -T agent-a pilotctl ping agent-b --timeout 5s >/dev/null 2>&1; then
    log_pass "ping agent-a → agent-b ok"
else
    log_fail "ping failed (EXPECTED: allow rules permit traffic)"
fi

log_test "cycle runs without error"
if $DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1; then
    log_pass "cycle ok"
else
    log_fail "cycle failed"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
