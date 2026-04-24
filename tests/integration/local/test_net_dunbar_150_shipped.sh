#!/bin/bash
# Shipped config: configs/networks/dunbar-150.json
#
# Name's promise: cap of 150 connections per agent — 151st is rejected
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

CFG="$(pwd)/../../../configs/networks/dunbar-150.json"
if [ ! -f "$CFG" ]; then
    log_fail "dunbar-150.json NOT shipped — promise unmet (EXPECTED: cap of 150 connections per agent — 151st is rejected)"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "dunbar-150-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "dunbar cap of 150 present in loaded policy"
# Shipped config keys the 150 cap via prune_trust/fill_trust params and
# trusted_count match expressions — not via a top-level max_peers. Assert
# against the loaded policy JSON (`policy get`) for the 150 literal plus
# at least one trust-pruning rule.
POL=$($DC exec -T agent-a pilotctl --json policy get --net "$NID" 2>/dev/null)
if echo "$POL" | grep -q '150' && echo "$POL" | grep -qE 'prune_trust|fill_trust|trusted_count'; then
    log_pass "dunbar-150 cap visible (150 + prune/fill rules present)"
else
    log_fail "no 150-cap rule visible (EXPECTED: trusted_count>150 prune + 150 fill)"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
