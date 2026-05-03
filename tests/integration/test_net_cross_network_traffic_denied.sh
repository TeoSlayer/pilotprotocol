#!/bin/bash
# Cross-network deny: network X has `connect:deny` for any non-member.
# agent-a joins X. agent-b does NOT join X (it's in a separate network
# Y). agent-b attempts to dial agent-a at an X-scoped port — X's
# connect:deny must reject the frame.
#
# Proves: X's gate event fires on inbound connect attempts from
# peers outside X, not just from members.

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

DC="docker compose -f docker-compose.multi.yml"
export DC
cd "$(dirname "$0")" || exit 1
source ./network_helpers.sh

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

DENY=$(mktemp -t "deny_XXXX.json")
cat > "$DENY" <<'EOF'
{
  "name": "deny-outsiders",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "deny-nonmember", "on": "connect",
       "match": "!has_tag(peer_tags, \"member\")",
       "actions": [{"type": "deny"}]},
      {"name": "allow-member", "on": "connect",
       "match": "has_tag(peer_tags, \"member\")",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

log_test "create strict network X (deny non-members)"
NID=$(create_network_from_file "$DENY" "deny-out-$$") || { log_fail "create"; exit 1; }
log_pass "net=$NID"

log_test "agent-a joins X; agent-b stays out"
start_agent_in_network agent-a "$NID" "$DENY"
sleep 2
assert_in_network agent-a "$NID" >/dev/null && log_pass "agent-a is member of X" \
    || log_fail "agent-a did not join X"

# agent-b does NOT join X — so from X's perspective, agent-b is a non-member.
# agent-b attempts to ping agent-a at an X-scoped address (if supported)
# or any service; the daemon must surface a policy-deny error.
log_test "agent-b (non-member of X) dials agent-a — expect deny"
# EXPECTED: connect-level deny surfaces as a non-zero exit + error
# message from pilotctl. If it succeeds, X's gate is not enforced
# against outsiders.
if $DC exec -T agent-b pilotctl send agent-a 1001 \
    --data "cross-network-probe" --timeout 5s >/tmp/x-deny.txt 2>&1; then
    # A successful send against a deny-all X means either X isn't
    # enforcing against non-members (scoping gap) or the send went
    # on the base network (expected — X's policy only gates traffic
    # that's tagged as flowing through X, which today may be
    # implicit-only).
    # EXPECTED: the test asserts a deny. A pass here is a FINDING.
    log_fail "cross-network send succeeded despite X's deny rule (EXPECTED: deny)"
    tail -5 /tmp/x-deny.txt | sed 's/^/    /'
else
    log_pass "send refused (policy deny fired)"
fi

rm -f "$DENY"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
