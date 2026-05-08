#!/bin/bash
# Matrix 4 — join × allow.
#
# FINDING: The pkg/policy schema declares `EventJoin` and `EventLeave` and
# env.go wires the variable namespace for them, but the daemon event path
# (pkg/daemon/daemon.go) only fires connect/dial/datagram/cycle. The
# register/join flow in pkg/registry does not call `EvaluateActions` with
# EventJoin. This test installs an allow-join policy and verifies that
# (a) the policy loads cleanly (compiles join rules) and (b) a second node
# joining the managed network via pilotctl succeeds with no regression.
# It does NOT currently assert the EventJoin directives fired, because
# the wiring is not implemented; a future daemon change that fires
# EventJoin should extend this test.

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
echo "Policy: join × allow (schema-level)"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply allow-join policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/join_allow.json; then
    log_fail "load (join rules may not be compiled)"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

log_test "agent-a joining managed network succeeds"
JOIN_OUT=$($DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a \
    pilotctl --json network join "$POLICY_NET_ID" 2>&1)
if echo "$JOIN_OUT" | grep -qE "joined|already"; then
    log_pass "join succeeded"
else
    # Some versions return JSON only
    if echo "$JOIN_OUT" | jq -e '.data' >/dev/null 2>&1; then
        log_pass "join ok ($(echo $JOIN_OUT | jq -r '.data.type // .type // .status // ""'))"
    else
        log_fail "join failed: $JOIN_OUT"
    fi
fi

log_test "agent-a member list contains agent-a and agent-b"
# Allow the registry to fully reflect both joins before querying.
sleep 2
MEMBERS=$($DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-b \
    pilotctl --json network members "$POLICY_NET_ID" 2>/dev/null \
    | jq -r '.data.nodes // .data.members // [] | length')
if [ "${MEMBERS:-0}" -ge 2 ]; then
    log_pass "members=$MEMBERS"
else
    log_fail "expected >=2 members, got $MEMBERS"
fi

log_test "FINDING: join event firing not wired in daemon"
echo "    (documented in test comment header)"

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
