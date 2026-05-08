#!/bin/bash
# Mutual-allow cross-network: two networks, each with `connect:allow`
# on any peer. Both agents join both networks. Traffic must flow both
# directions without policy interference.

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

ALLOW=$(mktemp -t "allow_XXXX.json")
cat > "$ALLOW" <<'EOF'
{
  "name": "allow-all",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "allow-any-connect", "on": "connect", "match": "true",
       "actions": [{"type": "allow"}]},
      {"name": "allow-any-dial",    "on": "dial",    "match": "true",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

log_test "create two mutually-permissive networks"
NID1=$(create_network_from_file "$ALLOW" "allow1-$$") || { log_fail "create 1"; exit 1; }
NID2=$(create_network_from_file "$ALLOW" "allow2-$$") || { log_fail "create 2"; exit 1; }
log_pass "nets = $NID1, $NID2"

log_test "both agents join both networks"
start_agent_in_network agent-a "$NID1" "$ALLOW"
start_agent_in_network agent-a "$NID2" "$ALLOW"
start_agent_in_network agent-b "$NID1" "$ALLOW"
start_agent_in_network agent-b "$NID2" "$ALLOW"
sleep 2

for nid in "$NID1" "$NID2"; do
    assert_in_network agent-a "$nid" >/dev/null && assert_in_network agent-b "$nid" >/dev/null \
        && log_pass "both in $nid" || log_fail "membership fail in $nid"
done

log_test "bidirectional traffic flows (a -> b)"
MSG="mutual-allow-$$"
RESP=$(echo "$MSG" | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 10s 2>/dev/null | tr -d '\r\n')
[ "$RESP" = "$MSG" ] && log_pass "a->b echo ok" || log_fail "a->b echo mismatch: got=$RESP want=$MSG"

log_test "bidirectional traffic flows (b -> a)"
RESP=$(echo "$MSG" | $DC exec -T agent-b pilotctl connect agent-a 7 --timeout 10s 2>/dev/null | tr -d '\r\n')
[ "$RESP" = "$MSG" ] && log_pass "b->a echo ok" || log_fail "b->a echo mismatch: got=$RESP want=$MSG"

rm -f "$ALLOW"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
