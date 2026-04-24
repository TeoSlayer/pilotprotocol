#!/bin/bash
# Shipped config: configs/networks/grudge-match.json
#
# Name's promise: persistent dispute — a deny event is remembered across sessions
#
# This test loads the shipped config (if present) and verifies the
# specific behavior implied by the network's name. If the config is
# not shipped or the policy engine cannot enforce the promise, the
# test fails — per Chunk I rules that failure is a product/engine
# gap finding, not a test bug.

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

CFG="$(pwd)/../../../configs/networks/grudge-match.json"
if [ ! -f "$CFG" ]; then
    log_fail "grudge-match.json NOT shipped — promise unmet (EXPECTED: persistent dispute — a deny event is remembered across sessions)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "grudge-match-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "denied peer stays on deny list across daemon restart"
PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r ".data.node_id // 0")
# Target A's network-1 address explicitly. Hostname resolution returns the
# backbone address (network 0), which has no policy runner — the grudge
# policy only fires when the datagram's dst address is in network $NID.
AGENT_A_NETADDR=$($DC exec -T agent-a pilotctl --json info 2>/dev/null \
    | jq -r ".data.networks[] | select(.network_id == ${NID}) | .address")
if [ -z "$AGENT_A_NETADDR" ]; then
    log_fail "agent-a has no address in network $NID"
    echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
    exit 1
fi
# Read peer_score via `managed rankings` (managed score is a write). Field:
#   .data.rankings[] = { rank, node_id, score, added_at, last_seen }
read_score() {
    $DC exec -T agent-a pilotctl --json managed rankings --net "$NID" 2>/dev/null \
        | jq -r ".data.rankings[] | select(.node_id == ${PEER_B}) | .score // 0"
}
# Simulate a violation (off-port datagram → first-strike: -10, deny).
# Datagrams reach the policy engine even without a listener at the dest;
# stream connects (`pilotctl send`) get RST-ed before the policy sees them
# if no listener is registered.
for i in 1 2 3; do
    $DC exec -T agent-b pilotctl dgram "$AGENT_A_NETADDR" 9999 --data grudge-$i >/dev/null 2>&1 || true
done
sleep 2
# Strengthened: verify grudge actually formed BEFORE restart. If peer_score
# isn't negative, nothing is being persisted and the post-restart check is
# meaningless.
SC_BEFORE=$(read_score)
SC_BEFORE=${SC_BEFORE:-0}
if [ "$SC_BEFORE" -ge 0 ] 2>/dev/null; then
    log_fail "grudge did not form: peer_score=$SC_BEFORE (EXPECTED: < 0 after off-port datagram)"
    echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
    exit 1
fi
$DC restart agent-a >/dev/null 2>&1
sleep 5
ensure_stack_up || true
# Grudge must survive restart — peer_score should still be negative.
SC_AFTER=$(read_score)
SC_AFTER=${SC_AFTER:-0}
if [ "$SC_AFTER" -ge 0 ] 2>/dev/null; then
    log_fail "grudge wiped by restart: $SC_BEFORE -> $SC_AFTER (EXPECTED: stays < 0)"
else
    log_pass "peer_score persisted: $SC_BEFORE -> $SC_AFTER"
fi
# Retry connect after restart — grudge-connect rule must deny.
# Use network-1 address so the policy evaluates (hostname → backbone bypasses it).
if echo retry | $DC exec -T agent-b pilotctl connect "$AGENT_A_NETADDR" 7 --timeout 3s >/dev/null 2>&1; then
    log_fail "peer rejoined after restart (EXPECTED: grudge persists)"
else
    log_pass "grudge persisted across restart"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
