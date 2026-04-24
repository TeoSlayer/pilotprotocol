#!/bin/bash
# Matrix 4 — datagram × deny.
# Under a deny-all datagram policy on agent-b, verify outbound send /
# publish datagrams from agent-a are dropped at ingress on agent-b and a
# datagram.port_rejected event is logged.
#
# NOTE: The daemon currently gates on pkt.Dst.Network, so a packet
# addressed to network 0 (the default/global) will NOT be evaluated
# against a policy installed on $POLICY_NET_ID. Tests that drive traffic
# only via hostname-to-addr lookup may be routed through net 0; this
# test treats a pass of the datagram as a finding rather than a bug in
# the test — see TEST-PLAN Chunk B.

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

DC="docker compose -f docker-compose.multi.policy.yml"

cd "$(dirname "$0")" || exit 1
. ./policy_helpers.sh

echo "=========================================="
echo "Policy: datagram × deny"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply deny-all datagram policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/deny_all_datagram.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

log_test "datagram under deny — expect policy deny log on receiver"
# Use dgram (real UDP datagram path). `pilotctl send` uses stream dial
# and fires connect/dial events, not datagram.
$DC exec -T agent-a timeout 8s pilotctl dgram agent-b 1001 --data "x" \
    >/tmp/dd-send.out 2>&1 || true
sleep 2
log_pass "dgram issued"

log_test "agent-b logs datagram rejection"
if assert_policy_event agent-b datagram_deny 1; then
    log_pass "rejection observed"
elif $DC logs agent-b 2>&1 | grep -qiE "datagram rejected: not allowed|datagram\.port_rejected"; then
    log_pass "rejection observed (log)"
else
    log_fail "no datagram_deny event observed"
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
