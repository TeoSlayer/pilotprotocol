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

DC="docker compose -f docker-compose.multi.yml"
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

log_test "agent-b attempts to join — expect deny"
if $DC exec -T agent-b pilotctl --json network join "$NID" >/tmp/j.txt 2>&1; then
    # The IPC call succeeded; check whether membership actually took.
    sleep 1
    if assert_in_network agent-b "$NID" >/dev/null; then
        # EXPECTED: if the daemon lists agent-b as a member despite the
        # join-deny rule, the join gate is not enforced.
        log_fail "agent-b joined despite join-deny rule (EXPECTED: rejected)"
    else
        log_pass "IPC returned ok but membership not recorded (join gate enforced post-hoc)"
    fi
else
    log_pass "join refused at IPC boundary"
fi

rm -f "$DENY"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
