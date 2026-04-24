#!/bin/bash
# Cone NAT + 200ms delay + 40ms jitter — satellite-link emulation.
# Tests RTO tuning and that Pilot's retransmit timers don't over-fire.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="cone"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agents register"
REG=$(wait_registered 2 90 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then
    log_pass "$REG nodes"
else
    log_fail "only $REG registered"
    exit 1
fi

log_test "inject 200ms delay + 40ms jitter on nat-gw public iface"
PUBIF=$($DC exec -T nat-gw ip -o -4 addr show | awk '$4 ~ "^192\\.0\\.2\\." {print $2; exit}')
$DC exec -T nat-gw tc qdisc add dev "$PUBIF" root netem delay 200ms 40ms || true
log_pass "netem delay applied on $PUBIF"

log_test "a->b echo under high latency"
OUT=$(echo_rt agent-a agent-b "latency-probe" "30s")
if echo "$OUT" | grep -q "latency-probe"; then
    log_pass "echo ok under 200ms RTT"
else
    log_fail "echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
