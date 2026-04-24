#!/bin/bash
# NAT traversal — full cone. Any external peer can reach agent-a's
# mapped endpoint once any outbound has opened it, because nat-gw DNATs
# all inbound high-port UDP back to agent-a.
#
# Expectation: a -> b direct works; b -> a direct (after trust) works
# without needing beacon hole-punch — because full-cone DNAT admits any
# new (src_ip, src_port) to the mapped port.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="full_cone"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "both agents register"
if REG=$(wait_registered 2 60); then
    log_pass "rendezvous sees $REG nodes"
else
    log_fail "only $REG nodes registered"
    exit 1
fi

log_test "a->b echo via full-cone"
OUT=$(echo_rt agent-a agent-b "fullcone-probe")
if echo "$OUT" | grep -q "fullcone-probe"; then
    log_pass "a->b echo ok"
else
    log_fail "a->b echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "establish trust a <-> b"
establish_trust agent-b agent-a >/dev/null
log_pass "trust set"

NID_A=$(agent_node_id agent-a)
AGENT_A_ADDR=$(pilot_addr "$NID_A")

log_test "b->a echo via full-cone (no hole-punch needed)"
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "fullcone-reverse")
if echo "$OUT" | grep -q "fullcone-reverse"; then
    log_pass "b->a echo ok via DNAT full-cone"
else
    log_fail "b->a echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
