#!/bin/bash
# Matrix 4 — datagram × allow.
# Under an allow-all datagram policy, verify that out-of-connection
# datagrams (send, publish) from agent-a to agent-b are accepted.
# The datagram gate runs once per packet in both directions (daemon.go
# lines 1815 ingress / 2386 egress).

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
echo "Policy: datagram × allow"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply allow-all datagram policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/allow_all_datagram.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

log_test "send text datagram agent-a → agent-b port 1001"
if $DC exec -T agent-a pilotctl send agent-b 1001 --data "datagram allow $$" --timeout 10s \
    >/tmp/d-send.out 2>&1; then
    log_pass "datagram accepted"
else
    log_fail "send rejected: $(tail -3 /tmp/d-send.out)"
fi

log_test "publish to agent-b (pubsub datagram path)"
if $DC exec -T agent-a pilotctl publish agent-b topic/x --data "data" \
    >/tmp/d-pub.out 2>&1; then
    log_pass "publish ok"
else
    log_fail "publish failed: $(tail -3 /tmp/d-pub.out)"
fi

log_test "no datagram rejections in agent-b logs"
N=$($DC logs agent-b 2>&1 | grep -cE "datagram\.port_rejected|datagram: rejected" || true)
if [ "${N:-0}" -eq 0 ]; then
    log_pass "no datagram rejections"
else
    log_fail "unexpected datagram rejections: $N"
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
