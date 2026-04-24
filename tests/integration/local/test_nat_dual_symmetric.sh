#!/bin/bash
# Dual-symmetric NAT: both agents behind symmetric gateways. Neither
# side can be the "public initiator" — both have random per-dest ports.
# Direct hole-punch is impossible; Pilot MUST fall back to beacon relay
# for the data path. This is where 'switching to relay' actually fires.
COMPOSE_FILE="docker-compose.multi.nat-dual.yml"
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE_A="symmetric"
export NAT_MODE_B="symmetric"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

$DC down -v >/dev/null 2>&1
log_test "boot dual-symmetric compose"
if ! $DC up -d --build rendezvous nat-gw-a nat-gw-b agent-a agent-b >/tmp/nat.dual.up.log 2>&1; then
    log_fail "compose up failed"
    tail -40 /tmp/nat.dual.up.log | sed 's/^/    /'
    exit 1
fi

log_test "both agents register"
REG=$(wait_registered 2 90 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "establish trust"
establish_trust agent-b agent-a >/dev/null
log_pass "trust set"

NID_A=$(agent_node_id agent-a)
AGENT_A_ADDR=$(pilot_addr "$NID_A")

log_test "b->a echo MUST go via relay (direct blocked both sides)"
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "dualsym-probe" "45s")
if echo "$OUT" | grep -q "dualsym-probe"; then log_pass "echo ok via relay"; else log_fail "echo failed: $(echo "$OUT" | head -c 200)"; fi

log_test "one of the agents logged 'switching to relay'"
if $DC logs agent-a agent-b 2>&1 | grep -q "direct dial timed out, switching to relay"; then
    log_pass "data-path relay fallback triggered"
else
    log_fail "no 'switching to relay' — direct dial unexpectedly worked under dual symmetric"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw-a nat-gw-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
