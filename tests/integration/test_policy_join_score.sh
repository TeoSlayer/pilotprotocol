#!/bin/bash
# Matrix 4 — join × score.
#
# FINDING: Same as test_policy_join_{allow,deny}.sh — EventJoin is
# compile-only today, not wired in the daemon's membership pipeline.
# This test installs a score-on-join policy with delta=10. Once the join
# event is wired to fire EvaluateActions, the score should be observable
# on agent-b's managed rankings after agent-a joins. Currently this test
# FAILs because join never fires.

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
echo "Policy: join × score"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply score-on-join policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/join_score.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

NID_A=$(node_id_of agent-a)

log_test "agent-a joins the network"
$DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a \
    pilotctl --json network join "$POLICY_NET_ID" >/tmp/join.out 2>&1 || true
sleep 3

log_test "agent-a peer score on agent-b reflects +10 join delta"
SCORE=$(policy_score_of agent-b "$POLICY_NET_ID" "$NID_A")
if [ "${SCORE:-0}" -ge 10 ] 2>/dev/null; then
    log_pass "score=$SCORE"
else
    log_fail "score=$SCORE (want >=10). FINDING: EventJoin not fired by daemon; directive is unreachable."
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
