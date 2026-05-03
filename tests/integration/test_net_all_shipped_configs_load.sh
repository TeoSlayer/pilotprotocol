#!/bin/bash
# Smoke test: every shipped configs/networks/*.json loads without error
# and the daemon reports the policy runner active on both agents. This
# is the generic "policy loaded" sweep — per-network behavioral asserts
# live in the individual test_net_<name>_shipped.sh files.
#
# Success criteria per config:
#   1. `pilotctl network create --rules-file <cfg>` returns a network_id
#      (registry validated the JSON + admin-token path works).
#   2. agent-a and agent-b `pilotctl network join <id>` succeed.
#   3. No panic/fatal in either daemon log.
#   4. `network list` on both agents shows the new id.
#
# Expected finding: if only 3 of ~35 promised configs exist on disk,
# this test passes for those 3 and prints a MISSING list for the rest.
# That missing list is itself a product/engine gap finding per Chunk I's
# RULES (name implies behavior not enforceable: test the name's promise).

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0
MISSING=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }
log_miss() { echo -e "[$(ts)] ${YELLOW}[MISS]${NC} $*"; MISSING=$((MISSING+1)); }

DC="docker compose -f docker-compose.multi.yml"
export DC

cd "$(dirname "$0")" || exit 1
source ./network_helpers.sh

log_test "bringing stack up"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
if ensure_stack_up; then
    log_pass "both agents registered"
else
    log_fail "stack failed to register"
    exit 1
fi

CONFIG_DIR="$(pwd)/../../configs/networks"
# Canonical list per Chunk I prompt — ~35 promised configs. Some may
# not yet exist on disk; those are findings, not test errors.
EXPECTED=(
    anti-camping aristocracy burnout cold-shoulder cooling-off
    data-exchange-policy dunbar-150 first-in-first-out forgiveness
    gift-economy golden-hour gossip-tax grudge-match half-life
    high-trust-society karma-ledger last-in-first-out lottery
    meritocracy meritocracy-rating mutual-admiration old-guard
    ostracism pay-it-forward rotating-chairs seniority small-circle
    stable-state sybil-gauntlet tithe trust-decay two-strikes
    vouching-chain whale-hunt
)

# Pre-scan for missing files so the report is up front.
log_test "scanning shipped configs in $CONFIG_DIR"
for name in "${EXPECTED[@]}"; do
    if [ ! -f "$CONFIG_DIR/$name.json" ]; then
        log_miss "$name.json not shipped (finding)"
    fi
done

# For each shipped file actually on disk, run the smoke.
for cfg in "$CONFIG_DIR"/*.json; do
    [ -f "$cfg" ] || continue
    base=$(basename "$cfg" .json)
    log_test "load $base"

    # Most shipped cycle rules default to "24h" which validates fine but
    # never ticks in CI. Override to 1m for this smoke (policy's
    # behavior is tested in the per-policy scripts).
    net_id=$(create_network_from_file "$cfg" "smoke-$base-$$" "1m" 2>/tmp/nc.err)
    if [ -z "$net_id" ]; then
        log_fail "$base: create_network_from_file failed: $(cat /tmp/nc.err)"
        continue
    fi

    start_agent_in_network agent-a "$net_id" "$cfg"
    start_agent_in_network agent-b "$net_id" "$cfg"
    sleep 1

    if assert_in_network agent-a "$net_id" >/dev/null && \
       assert_in_network agent-b "$net_id" >/dev/null; then
        log_pass "$base: joined (net_id=$net_id)"
    else
        log_fail "$base: one or both agents failed to join net_id=$net_id"
    fi
done

log_test "no panics in daemon logs"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 \
    | grep -iE 'panic|fatal|race detected' \
    | grep -vE 'log-level|--fatal' \
    | head -5)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "suspicious log lines:"; echo "$BAD" | sed 's/^/    /'
fi

echo
echo "=========================================="
echo "all-shipped-configs summary"
echo "=========================================="
echo -e "Shipped & loaded: ${GREEN}${PASSED}${NC}"
echo -e "Failed loads:     ${RED}${FAILED}${NC}"
echo -e "Missing configs:  ${YELLOW}${MISSING}${NC}  (product/engine gap finding)"
echo "=========================================="

# The test passes only if every SHIPPED config loaded. Missing configs
# are findings (the Chunk I RULE) — they do NOT fail the suite since
# they are a separate product-surface problem, but we emit MISSING count
# so CI reviewers can see them.
[ "$FAILED" -eq 0 ]
