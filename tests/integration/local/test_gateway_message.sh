#!/bin/bash
# Send a text message through the gateway's daemon to agent-b.
#
# pilot-gateway is a TCP proxy — message routing uses the gateway
# container's own pilot-daemon. "Send message via gateway" means
# pilotctl send-message runs inside the gateway container against
# agent-b over the overlay.
#
# EXPECTED: gateway daemon delivers the message to agent-b's inbox.

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
PASSED=0
FAILED=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.gateway.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Gateway: send-message to agent-b"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1

# Wait for 3 nodes registered (a, b, gateway's own daemon)
for _ in $(seq 1 90); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 3 ]; then break; fi
    sleep 1
done
if [ "${COUNT:-0}" -lt 3 ]; then
    log_fail "only $COUNT nodes registered (want >= 3: a, b, gateway)"
    $DC logs gateway | tail -20
    exit 1
fi
log_pass "stack up with gateway (total_nodes=$COUNT)"

# Clear agent-b's inbox before the test.
$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

PAYLOAD="gw-msg-$(date +%s)"

log_test "gateway daemon sends message to agent-b"
if ! $DC exec -T gateway pilotctl send-message agent-b --data "$PAYLOAD" --type text \
        >/tmp/gw-msg.out 2>&1; then
    log_fail "send-message from gateway failed"
    cat /tmp/gw-msg.out | head -10
fi

log_test "agent-b inbox contains the message within 15s"
FOUND=""
for _ in $(seq 1 30); do
    INBOX=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
    FOUND=$(echo "$INBOX" | jq -r --arg p "$PAYLOAD" \
        '[.data.messages[]? | select(.data == $p)] | .[0].data // empty')
    [ -n "$FOUND" ] && break
    sleep 0.5
done

if [ "$FOUND" = "$PAYLOAD" ]; then
    log_pass "message delivered: $FOUND"
else
    log_fail "message not found in inbox (payload=$PAYLOAD)"
    $DC exec -T agent-b pilotctl --json inbox 2>/dev/null | jq -r '.data.messages[]? | "  data=\(.data)"' | head -5
fi

log_test "no panics in any agent log"
BAD=$($DC logs rendezvous agent-a agent-b gateway 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
