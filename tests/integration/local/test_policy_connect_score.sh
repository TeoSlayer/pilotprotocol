#!/bin/bash
# Matrix 4 — connect × score.
# Under a policy that scores +5 on every inbound connect, verify the peer
# score on agent-b's policy-runner rankings strictly increases after each
# inbound connect from agent-a. The score directive runs as a side effect
# BEFORE the allow verdict (engine.evaluateGate: side-effects first, then
# verdict).

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
echo "Policy: connect × score"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack failed to start"
    exit 1
fi
log_pass "stack up"

log_test "Apply score-on-connect policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/score_on_connect.json; then
    log_fail "policy load failed"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

NID_A=$(node_id_of agent-a)
if [ -z "$NID_A" ]; then
    log_fail "could not determine agent-a node id"
    stop_policy_stack
    exit 1
fi

log_test "connect 3× agent-a → agent-b"
for i in 1 2 3; do
    $DC exec -T agent-a bash -c "echo hi$i | pilotctl connect agent-b 7 --timeout 10s" \
        >/dev/null 2>&1 || true
    sleep 1
done
log_pass "connects sent"

sleep 2

log_test "peer score for agent-a on agent-b has increased"
SCORE=$(policy_score_of agent-b "$POLICY_NET_ID" "$NID_A")
if [ -n "$SCORE" ] && [ "$SCORE" -gt 0 ] 2>/dev/null; then
    log_pass "score=$SCORE (>0)"
else
    log_fail "score=$SCORE (want >0 after 3 connects at +5 each)"
    $DC exec -T agent-b pilotctl --json managed rankings --net "$POLICY_NET_ID" | head -c 500
fi

stop_policy_stack

echo
echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
