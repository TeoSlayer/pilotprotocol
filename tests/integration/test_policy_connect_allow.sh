#!/bin/bash
# Matrix 4 — connect × allow.
# Apply a policy that allows every `connect` event on a managed network, then
# verify that an inbound connection from agent-a → agent-b completes and the
# policy runner is active on agent-b for the test network. The rule body is
# `true` with action `allow`, which the policy engine maps to DirectiveAllow.

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
echo "Policy: connect × allow"
echo "=========================================="

log_test "Starting stack with admin-token + policy overlay"
if start_policy_stack; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

log_test "Applying allow-all connect policy on agent-b"
if load_policy agent-b /tests/fixtures/policies/allow_all_connect.json; then
    log_pass "policy loaded (network_id=$POLICY_NET_ID)"
else
    log_fail "policy load failed"
    stop_policy_stack
    exit 1
fi

log_test "Policy runner is active on agent-b"
STATUS=$($DC exec -T agent-b pilotctl --json managed status --net "$POLICY_NET_ID" 2>&1)
ENGINE=$(echo "$STATUS" | jq -r '.data.engine // .engine // empty')
if [ "$ENGINE" = "policy" ]; then
    log_pass "engine=policy net=$POLICY_NET_ID"
else
    log_fail "policy runner not active (engine=$ENGINE status=$STATUS)"
fi

log_test "echo (connect+dial) agent-a → agent-b succeeds under allow-all"
MSG="allow-connect-$$"
RESP=$($DC exec -T agent-a bash -c "echo '$MSG' | pilotctl connect agent-b 7 --timeout 10s 2>/dev/null | tr -d '\r\n'")
if [ "$RESP" = "$MSG" ]; then
    log_pass "echo round-trip ok"
else
    log_fail "echo mismatch: got='$RESP' want='$MSG'"
fi

log_test "no deny/syn.port_rejected in agent-b logs"
BAD=$($DC logs agent-b 2>&1 | grep -cE "syn\.port_rejected|port_rejected" || true)
if [ "${BAD:-0}" -eq 0 ]; then
    log_pass "no rejections logged"
else
    log_fail "unexpected rejections observed (count=$BAD)"
fi

stop_policy_stack

echo
echo "=========================================="
echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
echo "=========================================="
[ "$FAILED" -eq 0 ]
