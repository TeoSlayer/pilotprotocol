#!/bin/bash
# Cone NAT with aggressively short UDP conntrack timeout (10s). If
# Pilot's 5s keepalive is operational, tunnels survive idle gaps; if
# not, the mapping expires mid-idle and reverse traffic is blocked.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="conntrack_short"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agents register"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then
    log_pass "$REG nodes"
else
    log_fail "only $REG registered"
    exit 1
fi

log_test "a->b initial echo"
OUT=$(echo_rt agent-a agent-b "ct-probe-1")
if echo "$OUT" | grep -q "ct-probe-1"; then
    log_pass "initial echo ok"
else
    log_fail "initial echo failed"
fi

log_test "establish trust + sleep 25s (idle > 10s conntrack UDP timeout)"
establish_trust agent-b agent-a >/dev/null
sleep 25
log_pass "idle period elapsed"

NID_A=$(agent_node_id agent-a)
AGENT_A_ADDR=$(pilot_addr "$NID_A")

log_test "b->a echo after idle (keepalive should have refreshed conntrack)"
OUT=$(echo_rt agent-b "$AGENT_A_ADDR" "ct-probe-2")
if echo "$OUT" | grep -q "ct-probe-2"; then
    log_pass "echo survived conntrack timeout window — keepalive works"
else
    log_fail "echo failed after idle — conntrack pruned, keepalive insufficient"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
