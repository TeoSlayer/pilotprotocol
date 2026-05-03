#!/bin/bash
# Matrix 4 — cycle × evict (via evict_where).
# Policy tags every connecting peer with "stale", then on each cycle evicts
# all peers matching has_tag(peer_tags, "stale"). After one connect and one
# forced cycle, the policy runner's peer count should drop back to zero (or
# pre-connect baseline).

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
echo "Policy: cycle × evict"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "Apply tag-then-evict policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/short_cycle_evict.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

NID_A=$(node_id_of agent-a)

# Bootstrap so agent-a is in the peer map (so tag add takes effect).
log_test "bootstrap peer set via cycle"
force_cycle agent-b "$POLICY_NET_ID" >/dev/null 2>&1 || true
sleep 1

log_test "connect agent-a → agent-b to trigger 'stale' tag"
$DC exec -T agent-a bash -c "echo x | pilotctl connect agent-b 7 --timeout 10s" \
    >/dev/null 2>&1 || true
sleep 2

log_test "agent-a has tag 'stale' after connect"
TAGS=$(policy_tags_of agent-b "$POLICY_NET_ID" "$NID_A")
if echo "$TAGS" | grep -q '"stale"'; then
    log_pass "tags=$TAGS"
else
    log_fail "expected 'stale' in tags, got $TAGS"
fi

log_test "force cycle -> evict stale peers"
COUNT_BEFORE=$(policy_peer_count agent-b "$POLICY_NET_ID")
force_cycle agent-b "$POLICY_NET_ID" >/tmp/cyc.out 2>&1
sleep 2
COUNT_AFTER=$(policy_peer_count agent-b "$POLICY_NET_ID")
if [ "${COUNT_AFTER:-99}" -lt "${COUNT_BEFORE:-0}" ]; then
    log_pass "peer_count $COUNT_BEFORE -> $COUNT_AFTER (evicted)"
else
    log_fail "peer_count did not shrink ($COUNT_BEFORE -> $COUNT_AFTER)"
fi

log_test "agent-b logged 'policy: evicted peers'"
if assert_policy_event agent-b evict 1; then
    log_pass "evict fired"
else
    log_fail "no evict log observed"
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
