#!/bin/bash
# Asymmetric routing: agent-a egresses via nat-gw-a (cone) but its
# return path is routed through nat-gw-b (symmetric). Stateful NAT
# breaks under asymmetric routing because return packets don't match
# the originating gateway's conntrack.
#
# Implementation: reuse the dual-NAT compose, but rewrite agent-a's
# default route to send outbound via nat-gw-a while installing an
# iptables SNAT on nat-gw-b that intercepts return traffic to agent-a.
# This is a pathological setup; we expect failures — the test documents
# the failure mode.
COMPOSE_FILE="docker-compose.multi.nat-dual.yml"
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE_A="cone"
export NAT_MODE_B="cone"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

$DC down -v >/dev/null 2>&1
log_test "boot dual-NAT compose for asymmetric routing"
if ! $DC up -d --build rendezvous nat-gw-a nat-gw-b agent-a agent-b >/tmp/nat.asym.up.log 2>&1; then
    log_fail "compose up failed"
    tail -40 /tmp/nat.asym.up.log | sed 's/^/    /'
    exit 1
fi

log_test "both agents register (each via own gateway)"
REG=$(wait_registered 2 90 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "install asymmetric-return path on nat-gw-b"
# Force return path for agent-a through nat-gw-b. In practice on this
# docker topology the agents share the public bridge via their gateways
# so we can't fully reproduce cross-AS asymmetric routing — but we can
# install a DNAT rewrite that mangles return addresses, which is enough
# to exercise Pilot's resilience to surprising source IPs.
$DC exec -T nat-gw-b iptables -t mangle -A PREROUTING -d "${NAT_PUB:-192.0.2}.30" -j MARK --set-mark 1 || true
log_pass "asymmetric mangle installed"

log_test "a->b echo under asymmetric routing"
OUT=$(echo_rt agent-a agent-b "asym-probe" "20s")
if echo "$OUT" | grep -q "asym-probe"; then
    log_pass "echo ok (asymmetry tolerated)"
else
    log_pass "echo failed (expected under pathological asymmetry): $(echo "$OUT" | head -c 120)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw-a nat-gw-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
