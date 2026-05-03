#!/bin/bash
# Matrix 4 — cycle × fill_trust.
# With zero trust links established and a fill_trust policy with target=10,
# force a cycle on agent-b; the runner should issue SendRequest for each
# candidate. Since there are only 2 agents in the stack, at most 1 request
# goes out. Assert the log line and that agent-a receives a pending
# handshake.

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
echo "Policy: cycle × fill_trust"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply fill_trust policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/short_cycle_fill_trust.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

log_test "confirm agent-b starts with 0 trust links"
B_START=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "${B_START:-0}" -eq 0 ]; then
    log_pass "trust set empty"
else
    log_fail "expected 0, got $B_START"
fi

log_test "force cycle"
force_cycle agent-b "$POLICY_NET_ID" >/tmp/cyc.out 2>&1
sleep 3
log_pass "cycle forced"

log_test "agent-b logged 'sent trust requests'"
if assert_policy_event agent-b fill_trust 1; then
    log_pass "fill_trust fired"
else
    log_fail "no fill_trust log observed"
    $DC logs agent-b 2>&1 | tail -30
fi

log_test "agent-a has a pending handshake from agent-b"
sleep 2
PENDING_A=$($DC exec -T agent-a pilotctl --json pending 2>/dev/null \
    | jq -r '.data.pending | length')
if [ "${PENDING_A:-0}" -ge 1 ]; then
    log_pass "agent-a pending=$PENDING_A"
else
    log_fail "agent-a pending=$PENDING_A (want >=1)"
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
