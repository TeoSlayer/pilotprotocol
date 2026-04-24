#!/bin/bash
# Stateful firewall (no NAT rewriting). agent-a keeps its private IP,
# gateway only filters unsolicited inbound. Contrasts NAT's two effects
# (filtering + rewriting) — this scenario has only filtering.
#
# In this harness agent-a still sits on a private subnet, so the
# rendezvous can't reach it inbound; agent-a's outbound registration
# goes through the gateway without translation. STUN will see the
# private IP and (correctly) discard it — so agent-a registers as
# a non-public node that must rely on registry-routed relay for
# inbound traffic.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="stateful_fw"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agents register through stateful firewall"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then
    log_pass "$REG nodes"
else
    log_fail "only $REG registered"
    exit 1
fi

log_test "agent-a endpoint is private (no NAT rewriting)"
EP=$(agent_endpoint agent-a)
echo "    endpoint=$EP"
EXPECT_PRV="${NAT_PRV:-198.51.100}."
if echo "$EP" | grep -qFe "$EXPECT_PRV" || [ -z "$EP" ]; then
    log_pass "endpoint private or discarded as expected"
else
    log_fail "unexpected endpoint: $EP"
fi

log_test "a->b echo via stateful firewall (outbound path)"
OUT=$(echo_rt agent-a agent-b "statefulfw-probe")
if echo "$OUT" | grep -q "statefulfw-probe"; then
    log_pass "a->b echo ok"
else
    log_fail "echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
