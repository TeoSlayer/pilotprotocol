#!/bin/bash
# NAT traversal — corporate firewall that only forwards TCP 9000/9001
# (rendezvous) and UDP 443/9001 (pilot beacon). Pilot's default :4000
# tunnel port is blocked on egress, so direct peer-to-peer fails. The
# daemon should detect and fall back to registry-relay over UDP 9001.
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="egress_443_only"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agent registrations (rendezvous TCP on 9000 permitted)"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then
    log_pass "$REG nodes registered"
else
    log_fail "only $REG registered — TCP 9000 should still pass"
fi

log_test "a->b echo succeeds via relay fallback (direct :4000 blocked)"
OUT=$(echo_rt agent-a agent-b "e443-probe" "30s")
if echo "$OUT" | grep -q "e443-probe"; then
    log_pass "echo ok — relay fallback compensates for restrictive egress"
else
    log_fail "echo failed: $(echo "$OUT" | head -c 200)"
fi

log_test "direct path attempted and failed (not just relayed on first try)"
if $DC logs agent-a 2>&1 | grep -qiE "direct handshake failed|switching to relay|relaying via registry"; then
    log_pass "daemon logged direct-failure + relay switch"
else
    log_fail "no direct-failure/relay log line found on agent-a"
fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
