#!/bin/bash
# Shipped config: configs/networks/high-trust-society.json
#
# Claim (per JSON):
#   - cycle: prune_trust when trusted_count > 100 (by score, 10%, min 100)
#   - cycle: fill_trust when trusted_count < 100 (target 100)
#   - connect: score +1 and allow
#   - datagram: score +1 and allow
#
# Assertion: the two scoring rules must tick the peer score by +1 per
# event. We produce N connects and expect score delta == N.

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

CFG="$(pwd)/../../configs/networks/high-trust-society.json"
[ -f "$CFG" ] || { log_fail "missing $CFG"; exit 1; }

NID=$(create_network_from_file "$CFG" "hts-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"

start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')

log_test "5 connects from a->b — score should be +5"
for i in 1 2 3 4 5; do
    echo "hts-$i" | $DC exec -T agent-a pilotctl connect agent-b 7 --timeout 5s >/dev/null 2>&1 || true
done
sleep 2

SC=$($DC exec -T agent-a pilotctl --json managed score "$NID" "$PEER_B" 2>/dev/null | jq -r '.data.score // 0')
if [ "${SC:-0}" -ge 5 ]; then
    log_pass "score=$SC (>= 5 expected)"
else
    # EXPECTED: score:+1 per connect rule should push score to at
    # least 5 after 5 connects.
    log_fail "score=$SC (EXPECTED >= 5; score action not applied per connect)"
fi

log_test "cycle tick runs without panic under active policy"
if $DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/tmp/hts.txt 2>&1; then
    log_pass "cycle ok"
else
    log_fail "cycle failed"; tail -3 /tmp/hts.txt | sed 's/^/    /'
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
