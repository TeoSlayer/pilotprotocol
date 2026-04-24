#!/bin/bash
# Multi-homed agent-a with two public interfaces. Verifies basic
# registration and connectivity when a node has multiple addresses.
COMPOSE_FILE="docker-compose.multi.nat-multihomed.yml"
source "$(dirname "$0")/nat_test_common.sh"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

$DC down -v >/dev/null 2>&1
log_test "boot multi-homed overlay"
if ! $DC up -d --build rendezvous agent-a agent-b >/tmp/nat.mh.up.log 2>&1; then
    log_fail "compose up failed"
    tail -40 /tmp/nat.mh.up.log | sed 's/^/    /'
    exit 1
fi

log_test "both agents register"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "agent-a registered one of its two endpoints"
EP=$(agent_endpoint agent-a)
echo "    endpoint=$EP"
EXPECT_PUB="${NAT_PUB:-192.0.2}.20"
EXPECT_PUB2="${NAT_PUB2:-203.0.113}.20"
if echo "$EP" | grep -qFe "$EXPECT_PUB" -e "$EXPECT_PUB2"; then
    log_pass "registered endpoint $EP"
else
    log_fail "unexpected endpoint: $EP"
fi

log_test "a->b echo"
OUT=$(echo_rt agent-a agent-b "mh-probe")
if echo "$OUT" | grep -q "mh-probe"; then log_pass "echo ok"; else log_fail "echo failed: $(echo "$OUT" | head -c 200)"; fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
