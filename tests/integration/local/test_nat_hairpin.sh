#!/bin/bash
# Hairpin NAT: both agents on private-a, reaching each other via the
# gateway's public IP. nat-gw runs NAT_MODE=hairpin which DNATs inbound
# private-side traffic aimed at the public IP back to the target agent.
COMPOSE_FILE="docker-compose.multi.nat-hairpin.yml"
source "$(dirname "$0")/nat_test_common.sh"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "both agents register (both private-side)"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "establish trust a <-> b"
establish_trust agent-a agent-b >/dev/null
log_pass "trust set"

NID_B=$(agent_node_id agent-b)
AGENT_B_ADDR=$(pilot_addr "$NID_B")

log_test "a->b echo (hairpin via gateway public IP)"
OUT=$(echo_rt agent-a "$AGENT_B_ADDR" "hairpin-probe" "20s")
if echo "$OUT" | grep -q "hairpin-probe"; then
    log_pass "hairpin echo ok"
else
    log_fail "hairpin echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
