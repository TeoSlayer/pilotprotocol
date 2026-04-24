#!/bin/bash
# Cone NAT + MTU black hole: ICMP frag-needed dropped, MTU clamped to
# 1200 on the public interface. Many real NATs do this and silently
# break PMTUD, causing stalled connections for large writes.
#
# Expectation: small echoes work; large writes should trigger
# path-MTU problems (Pilot should still deliver via segmentation).
source "$(dirname "$0")/nat_test_common.sh"
export NAT_MODE="cone"
cd "$(dirname "$0")" || exit 1
trap cleanup_nat EXIT

boot_nat_stack

log_test "agents register"
REG=$(wait_registered 2 60 || echo "0")
if [ "${REG:-0}" -ge 2 ]; then log_pass "$REG nodes"; else log_fail "only $REG"; exit 1; fi

log_test "clamp MTU to 1200 on nat-gw public iface and drop ICMP frag-needed"
PUBIF=$($DC exec -T nat-gw ip -o -4 addr show | awk '$4 ~ "^192\\.0\\.2\\." {print $2; exit}')
$DC exec -T nat-gw ip link set dev "$PUBIF" mtu 1200 || true
$DC exec -T nat-gw iptables -A FORWARD -p icmp --icmp-type fragmentation-needed -j DROP || true
log_pass "MTU 1200 + ICMP frag-needed drop installed"

log_test "small a->b echo (< MTU)"
OUT=$(echo_rt agent-a agent-b "mtu-small")
if echo "$OUT" | grep -q "mtu-small"; then log_pass "small echo ok"; else log_fail "small echo failed: $(echo "$OUT" | head -c 200)"; fi

log_test "no panics"
BAD=$($DC logs rendezvous agent-a agent-b nat-gw 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then log_pass "clean logs"; else log_fail "$BAD"; fi

print_summary_and_exit
