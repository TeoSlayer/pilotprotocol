#!/bin/bash
# Polo scoping per network: polo (reputation) accrued in network X
# must NOT apply in network Y. Each network keeps its own ledger.
#
# EXPECTED: if polo is today a single global ledger (not scoped by
# network), this test fails and the failure is a product finding —
# reputation leaking across networks is a trust boundary breach.

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

# Two networks; X scores +5 per connect, Y scores +0. After traffic,
# query per-network score for b-from-a viewpoint.
SCORE_X=$(mktemp -t "scoreX_XXXX.json")
cat > "$SCORE_X" <<'EOF'
{
  "name": "score-x",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "score", "on": "connect", "match": "true",
       "actions": [{"type": "score", "params": {"delta": 5}},
                   {"type": "allow"}]}
    ]
  }
}
EOF

SCORE_Y=$(mktemp -t "scoreY_XXXX.json")
cat > "$SCORE_Y" <<'EOF'
{
  "name": "score-y",
  "join_rule": "open",
  "expr_policy": {
    "version": 1,
    "rules": [
      {"name": "noop", "on": "connect", "match": "true",
       "actions": [{"type": "allow"}]}
    ]
  }
}
EOF

NID_X=$(create_network_from_file "$SCORE_X" "scoreX-$$") || { log_fail "create X"; exit 1; }
NID_Y=$(create_network_from_file "$SCORE_Y" "scoreY-$$") || { log_fail "create Y"; exit 1; }
log_pass "X=$NID_X Y=$NID_Y"

start_agent_in_network agent-a "$NID_X" "$SCORE_X"
start_agent_in_network agent-b "$NID_X" "$SCORE_X"
start_agent_in_network agent-a "$NID_Y" "$SCORE_Y"
start_agent_in_network agent-b "$NID_Y" "$SCORE_Y"
sleep 2

# Generate 3 connect events within X.
log_test "generate 3 connects a->b within X"
for i in 1 2 3; do
    echo "ping-$i" | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 5s >/dev/null 2>&1 || true
done
sleep 2

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')

log_test "score in X is >0 (X's rule awarded +5/connect)"
SC_X=$($DC exec -T agent-a pilotctl --json managed score "$NID_X" "$PEER_B" 2>/dev/null | jq -r '.data.score // 0')
if [ "${SC_X:-0}" -gt 0 ]; then
    log_pass "X score = $SC_X"
else
    log_fail "X score = $SC_X (expected >0)"
fi

log_test "score in Y is 0 (Y has no score rule — X's polo must NOT leak)"
SC_Y=$($DC exec -T agent-a pilotctl --json managed score "$NID_Y" "$PEER_B" 2>/dev/null | jq -r '.data.score // 0')
if [ "${SC_Y:-0}" = "0" ]; then
    log_pass "Y score = 0 (polo ledger is per-network)"
else
    # EXPECTED: if Y shows non-zero score, the ledger is shared across
    # networks — a scoping breach.
    log_fail "Y score = $SC_Y (EXPECTED: 0; polo leaked from X to Y)"
fi

rm -f "$SCORE_X" "$SCORE_Y"
echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
