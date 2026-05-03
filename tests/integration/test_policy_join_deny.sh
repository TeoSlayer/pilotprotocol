#!/bin/bash
# Matrix 4 — join × deny.
#
# FINDING: EventJoin is declared in pkg/policy but not wired into the
# registry/daemon membership path. The spec says this test should verify
# that a deny-join policy refuses `pilotctl network join`. Currently the
# deny is a no-op because the event never fires, so `network join` will
# succeed. That is a finding (documented-but-unimplemented event), not a
# test bug.
#
# The test still installs the policy (exercises compile), attempts the
# join, and fails loudly if the unimplemented path is later wired and this
# assertion needs to flip.

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
echo "Policy: join × deny"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply deny-join policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/join_deny.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

log_test "agent-a attempt to join: EXPECT deny when join wiring lands"
set +e
$DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a \
    pilotctl --json network join "$POLICY_NET_ID" \
    >/tmp/join-deny.out 2>&1
RC=$?
set -e

# Since join event is not yet fired, the join likely succeeds today.
# Record membership and flag appropriately.
MEMBERS=$($DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-b \
    pilotctl --json network members "$POLICY_NET_ID" 2>/dev/null \
    | jq -r '.data.members | length')

if [ $RC -ne 0 ] || [ "${MEMBERS:-0}" -lt 2 ]; then
    log_pass "join refused (rc=$RC members=$MEMBERS) — deny enforced"
else
    log_fail "join succeeded under deny policy (rc=$RC members=$MEMBERS). FINDING: EventJoin not wired in pkg/daemon; this test reproduces the gap."
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
