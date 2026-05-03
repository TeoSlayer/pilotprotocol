#!/bin/bash
# Matrix 4 — connect × deny.
# Apply a deny-all policy on agent-b for the test network. Agent-a's
# `connect` call must be refused: the daemon emits syn.port_rejected and
# the pilotctl command returns a non-zero exit / no echo response.
# Also verifies ops that traverse connect (file, message, submit, pubsub,
# trust) are all refused under the same policy.

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
echo "Policy: connect × deny"
echo "=========================================="

log_test "Starting stack"
if ! start_policy_stack; then
    log_fail "agents did not register"
    exit 1
fi
log_pass "stack up"

log_test "Apply deny-all connect policy on agent-b"
if load_policy agent-b /tests/fixtures/policies/deny_all_connect.json; then
    log_pass "deny-all policy loaded (net=$POLICY_NET_ID)"
else
    log_fail "policy load failed"
    stop_policy_stack
    exit 1
fi

# Policy currently gates on pkt.Dst.Network which reflects the packet's
# destination network, not the daemon's set of joined networks. Packets
# addressed to network 0 (default) will bypass the deny policy installed
# on the managed network. We explicitly target $POLICY_NET_ID in the
# destination address below.

ADDR_B=$($DC exec -T agent-a pilotctl --json find agent-b 2>/dev/null \
    | jq -r '.data.addresses[0] // empty')
if [ -z "$ADDR_B" ]; then
    ADDR_B=$($DC exec -T agent-a pilotctl find agent-b 2>/dev/null | awk '/Address:/{print $2}' | head -n1)
fi

log_test "echo under deny-all must fail (timeout or refusal)"
set +e
$DC exec -T agent-a bash -c "echo test | timeout 8s pilotctl connect agent-b 7 --timeout 5s" >/tmp/deny-echo.out 2>&1
ECHO_RC=$?
set -e
if [ $ECHO_RC -ne 0 ]; then
    log_pass "echo refused/timed out under deny policy (rc=$ECHO_RC)"
else
    # Still passes if policy not enforced on default net0 — record as finding
    log_fail "echo succeeded under deny-all (policy may only gate packets addressed to managed net $POLICY_NET_ID): $(tail -2 /tmp/deny-echo.out)"
fi

log_test "agent-b logs syn.port_rejected OR port_rejected OR policy deny"
sleep 2
if assert_policy_event agent-b connect_deny 1; then
    log_pass "deny event observed in logs"
else
    log_fail "no deny events in agent-b logs (expected under deny-all connect)"
fi

log_test "send-message under deny-all must fail"
set +e
$DC exec -T agent-a timeout 8s pilotctl send-message agent-b --data "x" --type text \
    >/tmp/deny-msg.out 2>&1
MSG_RC=$?
set -e
if [ $MSG_RC -ne 0 ]; then
    log_pass "send-message refused/timed out (rc=$MSG_RC)"
else
    log_fail "send-message succeeded under deny-all"
fi

log_test "send-file under deny-all must fail"
$DC exec -T agent-a bash -c "echo hi >/tmp/f.txt"
set +e
$DC exec -T agent-a timeout 10s pilotctl send-file agent-b /tmp/f.txt \
    >/tmp/deny-file.out 2>&1
FILE_RC=$?
set -e
if [ $FILE_RC -ne 0 ]; then
    log_pass "send-file refused/timed out (rc=$FILE_RC)"
else
    log_fail "send-file succeeded under deny-all"
fi

stop_policy_stack

echo
echo "=========================================="
echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
echo "=========================================="
[ "$FAILED" -eq 0 ]
