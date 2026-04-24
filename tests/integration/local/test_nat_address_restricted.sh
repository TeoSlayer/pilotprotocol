#!/bin/bash
# NAT traversal — address-restricted cone. Return traffic allowed from
# any port of a previously-contacted IP (not just the exact (ip,port)
# pair). Tests that Pilot's hole-punch still works when the remote's
# source port differs from what was originally observed.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="address_restricted"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "both agents register"
if REG=$(wait_registered 2 60); then
    log_pass "$REG nodes"
else
    log_fail "only $REG registered"
    exit 1
fi

log_test "a->b echo (address-restricted cone)"
OUT=$(echo_rt agent-a agent-b "addr-rest-probe")
if echo "$OUT" | grep -q "addr-rest-probe"; then
    log_pass "a->b echo ok"
else
    log_fail "a->b echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "establish trust"
establish_trust agent-b agent-a >/dev/null
log_pass "trust set"

NID_A=$(agent_node_id agent-a)
AGENT_A_ADDR=$(pilot_addr "$NID_A")

log_test "b->a echo via hole-punch (address-restricted)"
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "addr-rest-reverse")
if echo "$OUT" | grep -q "addr-rest-reverse"; then
    log_pass "b->a echo ok"
else
    log_fail "b->a echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
