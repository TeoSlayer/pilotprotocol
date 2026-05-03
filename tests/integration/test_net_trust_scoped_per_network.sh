#!/bin/bash
# Trust scoping per network: granting trust in X must NOT imply trust
# in Y. Each network maintains its own trust graph.
#
# EXPECTED: if `pilotctl trust grant` is network-agnostic today, a
# trust link granted while joined to X is visible from Y. That would
# be a trust-boundary breach.

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

ALLOW=$(mktemp -t "allow_XXXX.json")
cat > "$ALLOW" <<'EOF'
{
  "name": "allow-all",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "allow", "on": "connect", "match": "true",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

NID_X=$(create_network_from_file "$ALLOW" "trust-x-$$") || { log_fail "create X"; exit 1; }
NID_Y=$(create_network_from_file "$ALLOW" "trust-y-$$") || { log_fail "create Y"; exit 1; }
log_pass "X=$NID_X Y=$NID_Y"

start_agent_in_network agent-a "$NID_X" "$ALLOW"
start_agent_in_network agent-b "$NID_X" "$ALLOW"
start_agent_in_network agent-a "$NID_Y" "$ALLOW"
start_agent_in_network agent-b "$NID_Y" "$ALLOW"
sleep 2

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')

log_test "grant trust a->b (real CLI: handshake + approve)"
# FINDING: pilotctl has no network-scoped trust grant flag today.
# Real path: `handshake <peer>` on a, `approve <peer>` on b. All grants are
# currently global (unscoped by network). The test reveals whether scoping
# is implemented downstream of handshake — expected-fail until wired.
PEER_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
if $DC exec -T agent-a pilotctl handshake "$PEER_B" "scoping-probe" >/tmp/tg.txt 2>&1; then
    sleep 2
    $DC exec -T agent-b pilotctl approve "$PEER_A" >/dev/null 2>&1 || true
    log_pass "handshake initiated (scoping check follows in next assertion)"
else
    log_fail "handshake failed"; tail -5 /tmp/tg.txt | sed 's/^/    /'
fi
sleep 1

log_test "trust list filtered to X shows b"
LIST_X=$($DC exec -T agent-a pilotctl --json trust --network "$NID_X" 2>/dev/null \
    || $DC exec -T agent-a pilotctl --json trust 2>/dev/null)
if echo "$LIST_X" | grep -q "$PEER_B"; then
    log_pass "b in trust list for X"
else
    log_fail "b missing from X trust list"
fi

log_test "trust list filtered to Y does NOT show b"
LIST_Y=$($DC exec -T agent-a pilotctl --json trust --network "$NID_Y" 2>/dev/null)
if [ -n "$LIST_Y" ] && ! echo "$LIST_Y" | grep -q "$PEER_B"; then
    log_pass "Y trust list excludes b (per-network scoping enforced)"
else
    # EXPECTED: if Y's trust list contains b, the trust grant leaked
    # across networks.
    log_fail "b found in Y's trust list or --network flag not supported (EXPECTED: b absent from Y; product/engine gap)"
fi

rm -f "$ALLOW"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
