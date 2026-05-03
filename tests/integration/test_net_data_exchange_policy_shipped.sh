#!/bin/bash
# Shipped config: configs/networks/data-exchange-policy.json
#
# Claim (per JSON):
#   - connect:  allow if either side has tag "service"; else deny.
#   - dial:     allow if either side has tag "service"; else deny;
#               special-case: dial to port 7 (echo) always allowed.
#   - datagram: allow port 7 (echo), port 1000 (text); port 1001
#               (files) only when direction/tags match service; else deny.
#
# Assertions:
#   1. agent-b tagged as "service" accepts a connect from agent-a (no tag).
#   2. agent-b WITHOUT "service" tag rejects connect (unless echo).
#   3. echo port (7) is always dialable regardless of tags.
#   4. data-exchange port 1001 rejected when neither side is service.

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

CFG="$(pwd)/../../configs/networks/data-exchange-policy.json"
[ -f "$CFG" ] || { log_fail "missing $CFG"; exit 1; }

NID=$(create_network_from_file "$CFG" "dep-$$") || { log_fail "create"; exit 1; }
log_pass "net=$NID"

start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "echo (port 7) is always allowed (allow-echo-dial rule)"
RESP=$(echo "dep-echo-$$" | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 5s 2>/dev/null | tr -d '\r\n')
if [ -n "$RESP" ]; then
    log_pass "echo roundtrip ok ($RESP)"
else
    log_fail "echo blocked (EXPECTED: port 7 always allowed)"
fi

log_test "port 1001 rejected when neither side has 'service' tag"
# Agents start with no custom tags — confirm deny path.
$DC exec -T agent-a pilotctl clear-tags >/dev/null 2>&1
$DC exec -T agent-b pilotctl clear-tags >/dev/null 2>&1
sleep 1
if $DC exec -T agent-a pilotctl send agent-b 1001 --data "svc-probe" --timeout 3s >/tmp/dep.txt 2>&1; then
    log_fail "1001 send ACCEPTED without service tag (EXPECTED: deny)"
    tail -3 /tmp/dep.txt | sed 's/^/    /'
else
    log_pass "1001 send refused"
fi

log_test "port 1001 allowed once agent-b takes 'service' tag"
$DC exec -T agent-b pilotctl --json member-tags set --network "$NID" service >/dev/null 2>&1 \
    || $DC exec -T agent-b pilotctl set-tags service >/dev/null 2>&1
sleep 1
if $DC exec -T agent-a pilotctl send agent-b 1001 --data "svc-ok" --timeout 5s >/tmp/dep2.txt 2>&1; then
    log_pass "1001 allowed with service tag"
else
    # EXPECTED: tag-gated allow-service-files rule should open the
    # port once b is tagged service.
    log_fail "1001 blocked with service tag (EXPECTED: allowed)"
    tail -3 /tmp/dep2.txt | sed 's/^/    /'
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
