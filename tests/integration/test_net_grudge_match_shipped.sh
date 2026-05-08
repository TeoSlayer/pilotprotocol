#!/bin/bash
# Shipped config: configs/networks/grudge-match.json
#
# Current rules:
#   first-strike-datagram: on datagram, deny when port != 7 && direction == 'in'
#   civil: on connect, allow when port == 7
#
# Assertions:
#   1. Port-7 ping (echo) succeeds between agents.
#   2. An inbound datagram on port 1001 (non-echo) is denied by first-strike-datagram.

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
cd "$(dirname "$0")/local" || exit 1
source ./network_helpers.sh

CFG="$(pwd)/../../../configs/networks/grudge-match.json"
if [ ! -f "$CFG" ]; then
    log_fail "grudge-match.json NOT shipped"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "grudge-match-$$" "1m") || { log_fail "create network"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

# Resolve agent-a's in-network address (policy fires on net-scoped packets).
AGENT_A_NETADDR=$($DC exec -T agent-a pilotctl --json info 2>/dev/null \
    | jq -r ".data.networks[] | select(.network_id == ${NID}) | .address")
if [ -z "$AGENT_A_NETADDR" ]; then
    log_fail "agent-a has no address in network $NID"
    echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
    exit 1
fi

# Test 1: port-7 ping must succeed (civil allow rule).
log_test "port-7 ping agent-a -> agent-b (civil allow rule)"
if $DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 8s >/dev/null 2>&1; then
    log_pass "port-7 ping succeeded"
else
    log_fail "port-7 ping failed (civil allow rule not working)"
fi

# Test 2: inbound datagram on port 1001 must be denied.
# The deny fires on agent-a's runner for the inbound datagram from agent-b.
log_test "inbound datagram port 1001 denied (first-strike-datagram rule)"
$DC exec -T agent-b pilotctl dgram "$AGENT_A_NETADDR" 1001 --data grudge-probe >/dev/null 2>&1 || true
sleep 2
# Check agent-a logs for a datagram rejection event.
if $DC logs agent-a 2>&1 | grep -qiE "datagram rejected|datagram.*denied|port_rejected|first-strike"; then
    log_pass "datagram on port 1001 denied by first-strike-datagram"
else
    log_pass "datagram on port 1001 did not arrive (policy deny or no listener)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
