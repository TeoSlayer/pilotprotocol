#!/bin/bash
# Shipped config: configs/networks/small-circle.json
#
# Name's promise: small-circle — hard cap on peer count (e.g. max_peers=10)
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

CFG="$(pwd)/../../../configs/networks/small-circle.json"
if [ ! -f "$CFG" ]; then
    log_fail "small-circle.json NOT shipped — promise unmet (EXPECTED: small-circle — hard cap on peer count (e.g. max_peers=10))"
    exit 1
fi

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
ensure_stack_up || { log_fail "stack boot"; exit 1; }

NID=$(create_network_from_file "$CFG" "small-circle-$$" "1m") || { log_fail "create"; exit 1; }
log_pass "net=$NID"
start_agent_in_network agent-a "$NID" "$CFG"
start_agent_in_network agent-b "$NID" "$CFG"
sleep 2

log_test "small-circle trim/fill cycle pair loaded"
# small-circle uses fill_trust (target N) + prune_trust (>N) on cycle to
# hold the member count at a target; no explicit max_peers field. A
# 2-agent test can only verify the rule pair is active — fleet tests
# verify convergence.
POL=$($DC exec -T agent-a pilotctl --json policy get --net "$NID" 2>/dev/null)
TARGET=$(echo "$POL" | jq -r '.data.expr_policy.rules[]? | select(.name == "fill") | .actions[] | select(.type == "fill_trust") | .params.target // 0' | head -n1)
HAS_TRIM=$(echo "$POL" | jq -e '.data.expr_policy.rules[]? | select(.on == "cycle" and (.actions | map(.type) | index("prune_trust")))' >/dev/null 2>&1 && echo yes || echo no)
if [ "${TARGET:-0}" -gt 0 ] && [ "$HAS_TRIM" = yes ]; then
    log_pass "small-circle target=$TARGET trim+fill loaded"
else
    log_fail "small-circle rules missing: target=$TARGET trim=$HAS_TRIM"
fi

echo -e "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
