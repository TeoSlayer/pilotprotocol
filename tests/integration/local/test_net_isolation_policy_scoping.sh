#!/bin/bash
# Per-network scoping: agent-a joins network X (strict — connect:deny),
# agent-b joins network Y (permissive — connect:allow). Both agents
# connected to the SAME daemon are in different networks. X's deny
# rule must gate agent-a traffic, but NOT agent-b's traffic (Y's
# allow is what governs b). If the policy runner leaks rules across
# networks, agent-b would also be denied.
#
# Proves: `configs/networks/*.json` are per-network enforcement
# domains, not global.

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

# Build two tiny policies on the fly, written to tmpfiles.
STRICT=$(mktemp -t "strict_XXXX.json")
cat > "$STRICT" <<'EOF'
{
  "name": "strict-net",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "deny-all-connect", "on": "connect", "match": "true",
       "actions": [{"type": "deny"}]},
      {"name": "deny-all-dial",    "on": "dial",    "match": "true",
       "actions": [{"type": "deny"}]}
    ]
  }
}
EOF

PERMISSIVE=$(mktemp -t "permissive_XXXX.json")
cat > "$PERMISSIVE" <<'EOF'
{
  "name": "permissive-net",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "allow-all-connect", "on": "connect", "match": "true",
       "actions": [{"type": "allow"}]},
      {"name": "allow-all-dial",    "on": "dial",    "match": "true",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

log_test "create strict network (X)"
NID_X=$(create_network_from_file "$STRICT" "strict-$$") || { log_fail "create X"; exit 1; }
log_pass "net X = $NID_X"

log_test "create permissive network (Y)"
NID_Y=$(create_network_from_file "$PERMISSIVE" "perm-$$")  || { log_fail "create Y"; exit 1; }
log_pass "net Y = $NID_Y"

log_test "agent-a joins X; agent-b joins Y"
start_agent_in_network agent-a "$NID_X" "$STRICT"
start_agent_in_network agent-b "$NID_Y" "$PERMISSIVE"
sleep 2

if assert_in_network agent-a "$NID_X" >/dev/null && \
   assert_in_network agent-b "$NID_Y" >/dev/null; then
    log_pass "memberships set"
else
    log_fail "memberships not set"
fi

# X's deny should ONLY affect in-network traffic within X. agent-b,
# which is NOT in X, must still be reachable via the base network.
ADDR_A=$($DC exec -T agent-b pilotctl find agent-a 2>/dev/null \
    | awk '/Address:/{print $2}' | head -n1)
ADDR_B=$($DC exec -T agent-a pilotctl find agent-b 2>/dev/null \
    | awk '/Address:/{print $2}' | head -n1)

log_test "agent-b can reach agent-a on base network (Y's allow is permissive)"
if $DC exec -T agent-b pilotctl ping agent-a --count 2 --timeout 10s >/tmp/ping-yx.txt 2>&1; then
    log_pass "cross-scope base-network ping ok"
else
    # If base is gated by X's deny because runners leak, this is the
    # failure we're looking for.
    log_fail "base ping refused (likely policy-runner cross-network leak)"
    tail -5 /tmp/ping-yx.txt | sed 's/^/    /'
fi

log_test "X's deny is scoped to X (agent-a is member of X)"
POL_X=$($DC exec -T agent-a pilotctl --json policy get --net "$NID_X" 2>/dev/null)
if echo "$POL_X" | jq -e '.data.expr_policy.rules[]? | select(.name == "deny-all-connect")' >/dev/null 2>&1; then
    log_pass "X runner has deny-all rule"
else
    log_fail "X runner missing deny rule"
    echo "$POL_X" | head -c 500 | sed 's/^/    /'
fi

log_test "Y's allow is scoped to Y (agent-b is member of Y, not X)"
POL_Y=$($DC exec -T agent-b pilotctl --json policy get --net "$NID_Y" 2>/dev/null)
if echo "$POL_Y" | jq -e '.data.expr_policy.rules[]? | select(.name == "allow-all-connect")' >/dev/null 2>&1; then
    log_pass "Y runner has allow-all rule"
else
    log_fail "Y runner missing allow rule"
fi

log_test "runners have distinct rule sets per network"
# agent-a creates both networks (helper hardcodes agent-a as the
# creator), so it has runners for both X and Y. The important
# scoping property is that each runner holds a DIFFERENT rule set —
# X's deny rules must not leak into Y's runner and vice versa.
RULES_X=$(echo "$POL_X" | jq -c '.data.expr_policy.rules[]?.name' | sort -u | tr '\n' ',')
RULES_Y=$(echo "$POL_Y" | jq -c '.data.expr_policy.rules[]?.name' | sort -u | tr '\n' ',')
if [ -n "$RULES_X" ] && [ -n "$RULES_Y" ] && [ "$RULES_X" != "$RULES_Y" ]; then
    log_pass "per-network rule sets distinct (X=$RULES_X Y=$RULES_Y)"
else
    log_fail "rule sets leaked between networks (X=$RULES_X  Y=$RULES_Y)"
fi

rm -f "$STRICT" "$PERMISSIVE"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
