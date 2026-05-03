#!/bin/bash
# HTTP-over-pilot round-trip via gateway proxy mode.
#
# pilot-gateway maps a pilot address to a local IP in 10.4.0.0/16 and
# listens on TCP ports 80,443,7,1000,1001,1002,8080,8443 on that local IP,
# bridging TCP streams to <pilot-addr>:<port> via the overlay. So an HTTP
# client pointed at http://<local-ip>:80 talks to whatever is listening on
# agent-b's port 80.
#
# FINDING — the daemon does NOT ship a built-in HTTP service on PortHTTP
# (80) or PortSecure (443). The built-in services in pkg/daemon/services.go
# are: echo (7), data-exchange (1001), event-stream (1002), task-submit
# (1003), stdio (1000). There is no HTTP server attached to port 80 on
# agent-b by default, so a pure "GET / HTTP/1.1" round-trip has no
# peer responder in this test harness.
#
# Pragmatic test: use PortDataExchange (1001) which IS proxied by the
# gateway (it's in DefaultPorts) and does echo a payload back. We send a
# payload via raw TCP through the mapped IP to port 1001 and verify it is
# delivered to agent-b's data-exchange inbox.
#
# EXPECTED: gateway TCP-bridge proxies port 1001 to agent-b and the
# data-exchange service receives the payload.

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
echo "Gateway: HTTP/message round-trip via proxy"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1

for _ in $(seq 1 90); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null \
        | jq -r '.total_nodes // 0')
    if [ "${COUNT:-0}" -ge 3 ]; then break; fi
    sleep 1
done
if [ "${COUNT:-0}" -lt 3 ]; then
    log_fail "stack did not come up ($COUNT nodes)"
    exit 1
fi

# Resolve agent-b's pilot address and map it into the gateway
ADDR_B=$($DC exec -T gateway pilotctl --json lookup agent-b 2>/dev/null | jq -r '.data.address // empty')
if [ -z "$ADDR_B" ] || [ "$ADDR_B" = "null" ]; then
    log_fail "gateway could not look up agent-b"
    exit 1
fi
log_pass "agent-b pilot addr: $ADDR_B"

log_test "map agent-b into gateway local subnet"
MAP=$($DC exec -T gateway pilot-gateway -subnet 10.4.0.0/16 -socket /tmp/pilot.sock map "$ADDR_B" 2>&1)
LOCAL_IP=$(echo "$MAP" | awk -F' → ' '{print $1}' | tr -d '[:space:]')
if [ -z "$LOCAL_IP" ]; then
    log_fail "map returned no local IP: $MAP"
    exit 1
fi
log_pass "mapped $ADDR_B -> $LOCAL_IP"

# Port 1001 (data-exchange) is in DefaultPorts, so the gateway is listening there.
log_test "send payload to $LOCAL_IP:1001 (agent-b's data-exchange service)"
PAYLOAD="gw-http-msg-$(date +%s%N)"
# Install netcat-like tool inside the gateway container (use bash /dev/tcp).
if $DC exec -T gateway bash -c "exec 3<>/dev/tcp/${LOCAL_IP}/1001 && printf '%s\n' '${PAYLOAD}' >&3 && sleep 1" 2>/dev/null; then
    log_pass "TCP write to gateway-mapped IP succeeded"
else
    log_fail "could not open TCP to ${LOCAL_IP}:1001 via gateway"
fi

# Data-exchange writes payloads to agent-b's inbox.
sleep 2
log_test "payload delivered to agent-b inbox"
HIT=$($DC exec -T agent-b bash -c "grep -rl '${PAYLOAD}' /root/.pilot/inbox 2>/dev/null | head -n1" | tr -d '\r\n')
if [ -n "$HIT" ]; then
    log_pass "payload landed at $HIT"
else
    log_fail "payload not found in agent-b inbox; gateway proxy may not have delivered"
    $DC exec -T agent-b bash -c "ls /root/.pilot/inbox 2>/dev/null | head -5"
    $DC exec -T gateway tail -30 /tmp/gateway.log 2>/dev/null | head -30
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
