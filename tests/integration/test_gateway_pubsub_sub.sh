#!/bin/bash
# Subscribe to a topic from the gateway-side daemon and receive a message
# published from agent-a.
#
# EXPECTED: gateway passes through subscribe — the gateway-side subscriber
# observes the payload published by agent-a.

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
echo "Gateway: pubsub subscribe"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1

for _ in $(seq 1 90); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 3 ]; then break; fi
    sleep 1
done
[ "${COUNT:-0}" -lt 3 ] && { log_fail "stack did not come up"; exit 1; }

TOPIC="sensor/gw-sub-$(date +%s)"
PAYLOAD="gw-sub-data-$(date +%s%N)"

# Start subscriber on gateway container
$DC exec -d gateway bash -c "
    rm -f /tmp/gw-sub.log
    pilotctl subscribe gateway '$TOPIC' --timeout 25s > /tmp/gw-sub.log 2>&1 &
    echo \$! > /tmp/gw-sub.pid
"
sleep 3

log_test "agent-a publishes to gateway on $TOPIC"
if $DC exec -T agent-a pilotctl publish gateway "$TOPIC" --data "$PAYLOAD" >/tmp/a-pub.out 2>&1; then
    log_pass "publish issued"
else
    log_fail "publish from agent-a to gateway failed"
    $DC exec -T agent-a cat /tmp/a-pub.out 2>/dev/null | head -10
fi

sleep 3
log_test "gateway-side subscriber received payload"
SAW=$($DC exec -T gateway bash -c "grep -c '$PAYLOAD' /tmp/gw-sub.log 2>/dev/null || true" | tr -d '\r\n')
if [ "${SAW:-0}" -ge 1 ]; then
    log_pass "gateway subscriber saw payload ($SAW matches)"
else
    log_fail "gateway subscriber did not receive payload"
    $DC exec -T gateway cat /tmp/gw-sub.log 2>/dev/null | head -15
fi

$DC exec -T gateway bash -c 'kill $(cat /tmp/gw-sub.pid) 2>/dev/null' >/dev/null 2>&1

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
