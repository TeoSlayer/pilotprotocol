#!/bin/bash
# Join policy (deny): network with `join: deny` refuses membership;
# agent-b stays out.
#
# EXPECTED: the policy engine has an `EventJoin` type (pkg/policy/
# policy.go L23), but whether `pilotctl network join` runs the join
# rules gate is uncertain. If a deny rule on `on: join` does NOT
# block the join, that's a product/engine gap.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.policy.yml"
export DC
cd "$(dirname "$0")" || exit 1
source ./network_helpers.sh

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

DENY=$(mktemp -t "join_deny_XXXX.json")
cat > "$DENY" <<'EOF'
{
  "name": "join-deny",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "refuse-all", "on": "join", "match": "true",
       "actions": [{"type": "deny"}]},
      {"name": "gate",  "on": "connect", "match": "true",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

NID=$(create_network_from_file "$DENY" "join-deny-$$") || { log_fail "create"; exit 1; }
log_pass "net=$NID"

start_agent_in_network agent-a "$NID" "$DENY"
start_agent_in_network agent-b "$NID" "$DENY"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

log_test "join-deny rule evicts freshly-added peers from the runner"
# EventJoin fires when the runner's reconciler adds a peer. A `deny`
# directive on that event causes applyMembershipDiff to remove the peer
# right back out — peer_count should be 0 on both sides.
COUNT_A=$($DC exec -T agent-a pilotctl --json managed status --net "$NID" 2>/dev/null | jq '.data.peer_count // -1')
COUNT_B=$($DC exec -T agent-b pilotctl --json managed status --net "$NID" 2>/dev/null | jq '.data.peer_count // -1')
if [ "${COUNT_A:-1}" -eq 0 ] && [ "${COUNT_B:-1}" -eq 0 ]; then
    log_pass "join-deny evicted all peers (A peer_count=$COUNT_A, B peer_count=$COUNT_B)"
else
    log_fail "join-deny did not evict peers (A peer_count=$COUNT_A, B peer_count=$COUNT_B)"
fi

rm -f "$DENY"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
