#!/bin/bash
# Matrix 4 — datagram × score.
# Policy scores +3 on every datagram event. Drive N datagrams and verify
# the peer score increases on agent-b's rankings.
#
# Side-effect ordering: in engine.evaluateGate, non-verdict directives
# (score/tag) are accumulated across rules and emitted together with the
# first verdict, meaning the score side-effect runs whether the verdict
# came from the same rule or a later default allow.

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
echo "Policy: datagram × score"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply score-on-datagram policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/score_on_datagram.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

NID_A=$(node_id_of agent-a)

log_test "baseline score (may be empty for fresh peer)"
BASE=$(policy_score_of agent-b "$POLICY_NET_ID" "$NID_A")
log_pass "baseline score=${BASE:-<none>}"

log_test "drive 5 datagrams from agent-a"
for i in 1 2 3 4 5; do
    $DC exec -T agent-a pilotctl send agent-b 1001 --data "pkt-$i" --timeout 5s \
        >/dev/null 2>&1 || true
    sleep 0.2
done
log_pass "sent"

sleep 3
log_test "peer score increased"
NEW=$(policy_score_of agent-b "$POLICY_NET_ID" "$NID_A")
if [ -n "$NEW" ] && [ "${NEW:-0}" -gt "${BASE:-0}" ] 2>/dev/null; then
    log_pass "score increased: $BASE -> $NEW"
else
    log_fail "score not increased (base=$BASE new=$NEW)"
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
