#!/bin/bash
# Matrix 4 — cycle × prune_trust.
# TEST-PLAN calls for "cycle: 5s" but pkg/policy/policy.go:169 enforces a
# minimum of 1m, and pkg/daemon/policy_runner.go:508 silently promotes any
# <1m cycle to 24h at runtime. Finding: the short-cycle use case is NOT
# implemented. This test sets cycle to 1m (the minimum) and then uses
# `pilotctl managed cycle --force` to trigger the tick deterministically.
#
# Sequence:
#   1. handshake+approve agent-a <-> agent-b (establishes a trust link).
#   2. Install prune_trust policy with percent=100, min=0, by=score.
#   3. Force cycle on agent-b.
#   4. Assert both sides end with 0 trust links (prune fired).

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
echo "Policy: cycle × prune_trust"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "handshake + approve: establish trust"
$DC exec -T agent-a pilotctl --json handshake agent-b >/dev/null 2>&1
sleep 2
PENDING=$($DC exec -T agent-b pilotctl --json pending 2>/dev/null \
    | jq -r '.data.pending[0].node_id // empty')
if [ -n "$PENDING" ]; then
    $DC exec -T agent-b pilotctl --json approve "$PENDING" >/dev/null 2>&1
    sleep 3
fi
A_TRUSTED=$($DC exec -T agent-a pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
B_TRUSTED=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "${A_TRUSTED:-0}" -ge 1 ] && [ "${B_TRUSTED:-0}" -ge 1 ]; then
    log_pass "trust established (a=$A_TRUSTED b=$B_TRUSTED)"
else
    log_fail "trust not established (a=$A_TRUSTED b=$B_TRUSTED)"
    stop_policy_stack
    exit 1
fi

log_test "Apply short-cycle prune_trust policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/short_cycle_prune.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID, cycle=1m — enforcer minimum)"

log_test "force cycle on agent-b"
force_cycle agent-b "$POLICY_NET_ID" >/tmp/cyc.out 2>&1
sleep 3
log_pass "cycle forced"

log_test "agent-b trust set is empty (prune_trust fired)"
B_AFTER=$($DC exec -T agent-b pilotctl --json trust 2>/dev/null | jq -r '.data.trusted | length')
if [ "${B_AFTER:-1}" -eq 0 ]; then
    log_pass "trust set pruned to 0"
else
    log_fail "trust set still has $B_AFTER entries"
    $DC logs agent-b 2>&1 | tail -30
fi

log_test "agent-b logs 'policy: pruned trust links'"
if assert_policy_event agent-b prune_trust 1; then
    log_pass "prune_trust observed"
else
    log_fail "no prune_trust log observed"
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
