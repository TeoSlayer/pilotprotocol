#!/bin/bash
# Shipped config: configs/networks/meritocracy.json
#
# Current behavior:
#   - bottom: deny all dial connections (match: true)
#   - anyone: allow all datagrams (match: true)
#
# Assertions: config loads, datagrams are allowed, managed status is reachable.

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

CFG="$(pwd)/../../../configs/networks/meritocracy.json"
if [ ! -f "$CFG" ]; then
    log_fail "meritocracy.json NOT shipped"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "meritocracy-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "config loads — managed status succeeds"
STATUS=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null)
if echo "$STATUS" | jq -e '.data' >/dev/null 2>&1; then
    log_pass "managed status OK"
else
    log_fail "managed status returned no data"
fi

log_test "datagram traffic allowed (anyone rule)"
for i in 1 2 3; do
    $DC exec -T agent-b pilotctl dgram agent-a 7 --data "m-$i" >/dev/null 2>&1 || true
done
sleep 1
if $DC logs agent-a 2>&1 | grep -qiE "datagram rejected: not allowed|datagram\.port_rejected"; then
    log_fail "datagram rejected — meritocracy anyone rule should allow datagrams"
else
    log_pass "datagrams allowed by meritocracy policy"
fi

log_test "peers tracked in managed network"
COUNT=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null | jq '.data.peer_count // 0')
if [ "${COUNT:-0}" -gt 0 ]; then
    log_pass "peer_count=$COUNT — agents tracked in managed network"
else
    log_fail "no peers tracked in managed network (count=$COUNT)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
