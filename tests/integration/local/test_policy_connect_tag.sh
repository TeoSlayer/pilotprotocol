#!/bin/bash
# Matrix 4 — connect × tag.
# Under a policy that adds the tag "seen" to peer metadata on every inbound
# connect, verify the managed rankings for agent-b show agent-a with the
# "seen" tag after a single connect.
#
# Note: executeTag in pkg/daemon/policy_runner.go only tags peers that are
# ALREADY in the runner's peer map — if a peer is unknown, the add is a
# no-op. The score directive auto-creates the peer; tag does not. So we
# seed the peer set by running a cycle bootstrap first.

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
echo "Policy: connect × tag"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack failed to start"
    exit 1
fi
log_pass "stack up"

log_test "Apply tag-on-connect policy on agent-b"
if ! load_policy agent-b /tests/fixtures/policies/tag_on_connect.json; then
    log_fail "policy load failed"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

NID_A=$(node_id_of agent-a)

# Join agent-a into the policy network, then reconcile agent-b's runner
# so PEER_A is in its peer set — otherwise the on:connect tag directive
# bails (executeTag skips untracked peers).
$DC exec -T -e PILOT_ADMIN_TOKEN=test-admin-token agent-a pilotctl --json network join "$POLICY_NET_ID" >/dev/null 2>&1
sleep 1
log_test "Reconcile agent-b runner so PEER_A is tracked"
$DC exec -T agent-b pilotctl --json managed reconcile --net "$POLICY_NET_ID" >/dev/null 2>&1 || true
log_pass "reconciled"

log_test "connect agent-a → agent-b"
$DC exec -T agent-a bash -c "echo hi | pilotctl connect agent-b 7 --timeout 10s" \
    >/dev/null 2>&1 || true
sleep 2

log_test "agent-a peer has 'seen' tag on agent-b"
TAGS=$(policy_tags_of agent-b "$POLICY_NET_ID" "$NID_A")
if echo "$TAGS" | grep -q '"seen"'; then
    log_pass "tags=$TAGS"
else
    log_fail "tags=$TAGS (want to include 'seen')"
    $DC exec -T agent-b pilotctl --json managed rankings --net "$POLICY_NET_ID" | head -c 500
fi

stop_policy_stack

echo
echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
