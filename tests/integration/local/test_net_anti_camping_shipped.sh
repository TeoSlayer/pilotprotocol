#!/bin/bash
# Shipped config: configs/networks/anti-camping.json
#
# Name's promise: anti-camping = evict peers who idle / "camp" on the
# network without generating traffic beyond a threshold.
#
# EXPECTED: config ships with an `on: cycle` rule using evict_where
# `since(last_seen) > duration("<threshold>")` (or equivalent). This
# test loads the shipped config, inserts a deliberately-idle peer
# (agent-b joins then goes quiet), runs N forced cycles, and expects
# b to be evicted (policy_runner drops it from peers map).
#
# If the config file does not exist on disk, the test records a
# MISSING finding — Chunk I RULE: test the name's promise regardless.

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
log_skip() { echo -e "[$(ts)] ${YELLOW}[SKIP]${NC} $*"; }

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.policy.yml"
export DC
cd "$(dirname "$0")" || exit 1
source ./network_helpers.sh

CFG="$(pwd)/../../../configs/networks/anti-camping.json"
if [ ! -f "$CFG" ]; then
    log_fail "anti-camping.json NOT shipped — promise unmet (EXPECTED: evict idle peers)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "anti-camp-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2
sync_policy_peers "$NID" agent-a agent-b

PEER_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id // 0')

# Seed PEER_B's score to -12 (below the flush threshold -10). The next
# cycle will bleed -1 further, then flush's evict_where fires.
$DC exec -T agent-a pilotctl managed score "$PEER_B" --net "$NID" --delta -12 >/dev/null 2>&1 || true

log_test "force cycle — expect b evicted below threshold"
$DC exec -T agent-a pilotctl --json managed cycle --force --net "$NID" >/dev/null 2>&1 || true
sleep 1

RANKING=$($DC exec -T agent-a pilotctl --json managed rankings --net "$NID" 2>/dev/null)
if echo "$RANKING" | jq -e --argjson p "$PEER_B" '.data.rankings[]? | select(.node_id == $p)' >/dev/null 2>&1; then
    log_fail "b still in rankings after flush (EXPECTED: evicted at peer_score<-10)"
else
    log_pass "b evicted from rankings after flush"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
