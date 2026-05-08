#!/bin/bash
# Join policy (allow): a network with `join: allow` accepts new
# members. agent-b successfully joins.

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

ALLOW=$(mktemp -t "join_allow_XXXX.json")
cat > "$ALLOW" <<'EOF'
{
  "name": "join-allow",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "admit", "on": "join", "match": "true",
       "actions": [{"type": "allow"}]},
      {"name": "gate",  "on": "connect", "match": "true",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

NID=$(create_network_from_file "$ALLOW" "join-allow-$$") || { log_fail "create"; exit 1; }
log_pass "net=$NID"

log_test "agent-b joins — join:allow should admit"
if $DC exec -T agent-b pilotctl --json network join "$NID" >/tmp/j.txt 2>&1; then
    log_pass "join accepted"
else
    log_fail "join rejected despite allow rule"; tail -5 /tmp/j.txt | sed 's/^/    /'
fi

sleep 1
if assert_in_network agent-b "$NID" >/dev/null; then
    log_pass "agent-b membership visible"
else
    log_fail "agent-b not listed as member"
fi

rm -f "$ALLOW"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
