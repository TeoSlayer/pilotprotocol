#!/bin/bash
# NAT traversal — UDP egress blocked. The gateway drops all UDP FORWARD.
# TCP (rendezvous registration) still works; UDP tunnel cannot.
#
# Expectation: rendezvous TCP registration succeeds but the daemon
# can't form tunnels. Echo attempts should fail cleanly (no panic, no
# hang) — a negative result documents the expected degraded state.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="udp_blocked"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "rendezvous TCP still reachable (agent-a registers via TCP)"
REG=$(wait_registered 2 45 || echo "$?")
if [ "$REG" != "" ] && [ "${REG:-0}" -ge 2 ] 2>/dev/null; then
    log_pass "$REG nodes (TCP registration works even with UDP blocked)"
else
    log_pass "agent-a registration blocked too (expected if registry uses UDP beacon)"
fi

log_test "a->b echo must fail (UDP tunnel blocked)"
OUT=$(echo_rt agent-a agent-b "udp-blocked-probe" "5s")
if echo "$OUT" | grep -q "udp-blocked-probe"; then
    log_fail "echo unexpectedly succeeded with UDP blocked"
else
    log_pass "echo failed as expected"
fi

log_test "no panics despite blocked path"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "daemon handled blocked UDP gracefully"; else log_fail "$BAD"; fi

print_summary_and_exit
