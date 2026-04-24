#!/bin/bash
# Rotate identity key via the gateway-side daemon.
# Exercises `pilotctl rotate-key` through the gateway stack: the daemon
# generates a new keypair, signs `rotate:<node_id>:<new_public_key>` with
# the current key, registry swaps the pubkey, daemon persists it.

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
echo "Gateway: rotate-key"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "${COUNT:-0}" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

NODE_ID=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty')
PRE=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.public_key // empty')
[ -n "$NODE_ID" ] && [ -n "$PRE" ] || { log_fail "info missing"; exit 1; }

log_test "rotate-key on agent-a via gateway stack"
ROT=$($DC exec -T agent-a pilotctl --json rotate-key 2>&1)
if [ $? -ne 0 ]; then
    log_fail "rotate-key rc=$?: $ROT"
    exit 1
fi
POST=$(echo "$ROT" | jq -r '.data.public_key // empty')
if [ -n "$POST" ] && [ "$POST" != "$PRE" ]; then
    log_pass "pubkey rotated ($PRE -> $POST)"
else
    log_fail "pubkey unchanged or missing in response: $ROT"
fi

log_test "registry lookup returns new pubkey"
LOOKUP=$($DC exec -T agent-a pilotctl --json lookup "$NODE_ID" 2>/dev/null | jq -r '.data.public_key // empty')
if [ "$LOOKUP" = "$POST" ]; then
    log_pass "registry reflects rotated pubkey"
else
    log_fail "registry lookup=$LOOKUP expected=$POST"
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
