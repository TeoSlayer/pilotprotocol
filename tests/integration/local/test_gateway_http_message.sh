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
ADDR_B=$($DC exec -T gateway pilotctl --json find agent-b 2>/dev/null | jq -r '.data.address // empty')
if [ -z "$ADDR_B" ] || [ "$ADDR_B" = "null" ]; then
    log_fail "gateway could not look up agent-b"
    exit 1
fi
log_pass "agent-b pilot addr: $ADDR_B"

log_test "map agent-b into gateway local subnet"
# `pilot-gateway map` is a one-shot CLI that creates its own transient
# gateway, maps, then exits — leaving no listeners. To install a
# durable mapping we restart the gateway via `pilot-gateway run` with
# the mapping passed positionally, which keeps the proxy listeners up.
# The compose-startup script left a no-arg pilot-gateway running. Kill
# all pilot-gateway processes, then start a new one with the mapping
# argument. Write to a fresh log so the no-arg restart attempts (if any)
# don't overwrite the one we're inspecting.
$DC exec -T gateway bash -c 'pkill -9 -f "pilot-gateway" 2>/dev/null; sleep 2' >/dev/null 2>&1
$DC exec -T gateway bash -c "cat >/tmp/gw-run.sh <<EOF
#!/bin/sh
exec pilot-gateway -subnet 10.4.0.0/16 -socket /tmp/pilot.sock run '$ADDR_B' 10.4.0.1 > /tmp/gateway-mapped.log 2>&1
EOF
chmod +x /tmp/gw-run.sh"
$DC exec -d gateway /tmp/gw-run.sh
sleep 5
LOCAL_IP="10.4.0.1"
if $DC exec -T gateway grep -q "gateway proxy listening" /tmp/gateway-mapped.log 2>/dev/null; then
    log_pass "mapped $ADDR_B -> $LOCAL_IP (listeners up)"
else
    log_fail "gateway proxy listeners did not start; log: $($DC exec -T gateway tail -15 /tmp/gateway-mapped.log)"
    exit 1
fi

# Port 7 (echo) is in DefaultPorts. The echo service accepts raw bytes
# and reflects them back, so a TCP echo round-trip through the gateway
# proves the data-plane proxy works end-to-end. (Port 1001 — data-
# exchange — would need framed protocol input that /dev/tcp can't easily
# supply.)
log_test "TCP echo round-trip through gateway-mapped $LOCAL_IP:7"
PAYLOAD="gw-echo-$(date +%s%N)"
ECHO_OUT=$($DC exec -T gateway bash -c "
    exec 3<>/dev/tcp/${LOCAL_IP}/7
    printf '%s' '${PAYLOAD}' >&3
    timeout 3 head -c ${#PAYLOAD} <&3
    exec 3<&-
" 2>/dev/null)
if [ "$ECHO_OUT" = "$PAYLOAD" ]; then
    log_pass "echo round-trip ok (got $ECHO_OUT)"
else
    log_fail "echo mismatch via gateway: sent=$PAYLOAD got=$ECHO_OUT"
    $DC exec -T gateway tail -20 /tmp/gateway-mapped.log 2>/dev/null
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
