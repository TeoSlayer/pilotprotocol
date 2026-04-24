#!/bin/bash
# Publish an event via the gateway-side daemon.
#
# EXPECTED: gateway passes through publish — agent-a (subscriber) receives
# an event on the topic.

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
echo "Gateway: pubsub publish"
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

TOPIC="sensor/gw-pub-$(date +%s)"
PAYLOAD="temp=42.1"

# agent-a subscribes in the background, writing events to a file.
$DC exec -d agent-a bash -c "
    rm -f /tmp/sub.log
    pilotctl subscribe agent-a '$TOPIC' --timeout 20s > /tmp/sub.log 2>&1 &
    echo \$! > /tmp/sub.pid
"
sleep 2

log_test "publish '$TOPIC' via gateway daemon"
if $DC exec -T gateway pilotctl publish agent-a "$TOPIC" --data "$PAYLOAD" >/tmp/gw-pub.out 2>&1; then
    log_pass "publish returned ok"
else
    log_fail "publish via gateway failed"
    $DC exec -T gateway cat /tmp/gw-pub.out 2>/dev/null | head -10
fi

sleep 3
log_test "subscriber on agent-a saw payload"
SAW=$($DC exec -T agent-a bash -c "grep -c '$PAYLOAD' /tmp/sub.log 2>/dev/null || true" | tr -d '\r\n')
if [ "${SAW:-0}" -ge 1 ]; then
    log_pass "subscriber received payload ($SAW matches)"
else
    log_fail "subscriber never saw payload"
    $DC exec -T agent-a cat /tmp/sub.log 2>/dev/null | head -15
fi

# Cleanup subscriber
$DC exec -T agent-a bash -c 'kill $(cat /tmp/sub.pid) 2>/dev/null' >/dev/null 2>&1

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
