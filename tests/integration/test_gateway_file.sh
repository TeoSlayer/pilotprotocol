#!/bin/bash
# Send a file through the gateway's file-transfer path to agent-b.
#
# pilot-gateway is a TCP proxy — it does not have a dedicated file-transfer
# endpoint. The gateway container's daemon handles send-file; tests run
# pilotctl inside the gateway container to exercise the same send-file
# dataplane used in test_p2p.sh.
#
# EXPECTED: gateway passes through send-file — file arrives at agent-b
# with matching sha256.

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
echo "Gateway: send-file agent-b"
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
log_pass "stack up ($COUNT nodes)"

log_test "gateway sends 4 KiB file to agent-b"
$DC exec -T gateway bash -c 'head -c 4096 /dev/urandom >/tmp/gw-f.bin' >/dev/null 2>&1
SRC=$($DC exec -T gateway sha256sum /tmp/gw-f.bin | awk '{print $1}')

if ! $DC exec -T gateway timeout 30 pilotctl send-file agent-b /tmp/gw-f.bin >/tmp/send-gw.out 2>&1; then
    log_fail "send-file from gateway failed"
    $DC exec -T gateway cat /tmp/send-gw.out 2>/dev/null | head -10
fi

RECV=$($DC exec -T agent-b bash -c "ls -t /root/.pilot/received 2>/dev/null | grep -E '^gw-f-' | head -n1" | tr -d '\r\n')
if [ -z "$RECV" ]; then
    # Some builds keep the original basename. Accept either.
    RECV=$($DC exec -T agent-b bash -c "ls -t /root/.pilot/received 2>/dev/null | head -n1" | tr -d '\r\n')
fi

DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" 2>/dev/null | awk '{print $1}')
fi

if [ -n "$DST" ] && [ "$SRC" = "$DST" ]; then
    log_pass "file received ok (sha=${SRC:0:12}...)"
else
    log_fail "file mismatch: src=${SRC:0:12}... dst=${DST:0:12}... recv=$RECV"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
