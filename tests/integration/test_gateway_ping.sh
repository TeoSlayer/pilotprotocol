#!/bin/bash
# Ping agent-b via the gateway container.
#
# NOTE on "via gateway": pilot-gateway is a TCP-bridge proxy, not a
# control-plane API. It does not proxy pilotctl commands. This test
# exercises the gateway-side daemon: the gateway container runs its own
# pilot-daemon, so "ping through gateway" = pilotctl ping from inside
# the gateway container against agent-b over the overlay.
#
# EXPECTED: gateway-side daemon ping of agent-b succeeds.

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
echo "Gateway: ping agent-b"
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
    $DC logs gateway | tail -40
    exit 1
fi
log_pass "stack up with gateway (total_nodes=$COUNT)"

log_test "pilotctl ping agent-b from inside gateway container"
if $DC exec -T gateway pilotctl ping agent-b --count 3 --timeout 10s >/tmp/gw-ping.out 2>&1; then
    log_pass "ping agent-b via gateway daemon ok"
else
    log_fail "ping agent-b via gateway daemon failed"
    $DC exec -T gateway tail -20 /tmp/gw-ping.out 2>/dev/null || true
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
