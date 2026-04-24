#!/bin/bash
# Cone NAT — register successfully, establish a tunnel, then drop the
# agent-a <-> rendezvous path mid-flight and verify the existing tunnel
# keeps working (tunnels shouldn't need the rendezvous once established).
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="cone"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agents register"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "establish initial a->b echo"
OUT=$(echo_rt agent-a agent-b "pre-partition")
if echo "$OUT" | grep -q "pre-partition"; then log_pass "tunnel up"; else log_fail "initial echo failed: $(echo "$OUT" | head -c 200)"; fi

# Pre-resolve agent-b's pilot address before partitioning the rendezvous.
# Dialing by hostname after partition would require a registry lookup,
# which would fail independently of the tunnel. We want to prove the
# tunnel itself survives, so we skip hostname resolution entirely.
NID_B=$(agent_node_id agent-b)
AGENT_B_ADDR=$(pilot_addr "$NID_B")
echo "    pre-resolved agent-b=$AGENT_B_ADDR"

log_test "partition: drop agent-a -> rendezvous traffic"
# Block agent-a (private.20) from reaching rendezvous (public.10).
A_IP="${NAT_PRV:-198.51.100}.20"
R_IP="${NAT_PUB:-192.0.2}.10"
$DC exec -T nat-gw iptables -I FORWARD 1 -s "$A_IP" -d "$R_IP" -j DROP || true
$DC exec -T nat-gw iptables -I FORWARD 1 -s "$R_IP" -d "$A_IP" -j DROP || true
log_pass "partition rules installed"

sleep 3

log_test "existing tunnel survives partition (a->b echo still works)"
OUT=$(echo_rt agent-a "$AGENT_B_ADDR" "post-partition")
if echo "$OUT" | grep -q "post-partition"; then
    log_pass "echo survived — tunnel independent of rendezvous"
else
    log_fail "echo failed after partition — tunnel shouldn't need rendezvous: $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
