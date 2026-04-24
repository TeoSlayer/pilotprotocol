#!/bin/bash
# Carrier-grade / double NAT: agent-a behind home NAT behind CGN.
# Common on mobile networks. Tests whether Pilot's STUN + hole-punch
# survive two layers of address translation.
COMPOSE_FILE="docker-compose.multi.nat-cgn.yml"
source "$(dirname "$0")/nat_test_common.sh"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

$DC down -v >/dev/null 2>&1
log_test "boot double-NAT overlay"
if ! $DC up -d --build rendezvous nat-gw-cgn nat-gw-home agent-a agent-b >/tmp/nat.cgn.up.log 2>&1; then
    log_fail "compose up failed"
    tail -40 /tmp/nat.cgn.up.log | sed 's/^/    /'
    exit 1
fi

log_test "both agents register through double NAT"
REG=$(wait_registered 2 90 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "agent-a endpoint is CGN's public IP (not home NAT private)"
EP=$(agent_endpoint agent-a)
echo "    endpoint=$EP"
EXPECT_PUB="${NAT_PUB:-192.0.2}.30"
EXPECT_CGN="${NAT_CGN:-100.64.0}."
if echo "$EP" | grep -qF "$EXPECT_PUB"; then
    log_pass "endpoint is CGN public ($EP)"
elif echo "$EP" | grep -qE "10\\.|${EXPECT_CGN}"; then
    log_fail "endpoint leaks intermediate address: $EP"
else
    log_fail "unexpected endpoint: $EP"
fi

log_test "a->b echo through double NAT"
OUT=$(echo_rt agent-a agent-b "cgn-probe" "25s")
if echo "$OUT" | grep -q "cgn-probe"; then log_pass "echo ok"; else log_fail "echo failed: $(echo "$OUT" | head -c 200)"; fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw-home nat-gw-cgn 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
