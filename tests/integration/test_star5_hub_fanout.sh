#!/bin/bash
# Star-5 hub fan-out: hub publishes a distinct event to each of 4 leaves
# simultaneously. All 4 leaves must receive their event.

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

DC="docker compose -f docker-compose.star5hub.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Star-5 hub fan-out"
echo "=========================================="

log_test "Starting star stack (hub + 4 leaves)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous hub leaf-1 leaf-2 leaf-3 leaf-4 >/dev/null 2>&1
if COUNT=$(wait_all_registered 5 rendezvous); then
    log_pass "5 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

TOPIC="star-$(date +%s)"

log_test "start 4 leaf subscribers (each on its own subscribe to the same topic)"
for i in 1 2 3 4; do
    $DC exec -d "leaf-$i" bash -c "pilotctl --json subscribe leaf-$i $TOPIC --count 1 --timeout 30s > /tmp/sub.log 2>&1"
done
sleep 3
log_pass "leaf subscribers running"

log_test "hub publishes distinct payloads to all 4 leaves (parallel)"
for i in 1 2 3 4; do
    $DC exec -T hub pilotctl --json publish "leaf-$i" "$TOPIC" --data "to-leaf-$i" >/dev/null 2>&1 &
done
wait
sleep 6

GOT=0
for i in 1 2 3 4; do
    out=$($DC exec -T "leaf-$i" cat /tmp/sub.log 2>/dev/null)
    if echo "$out" | jq -e --arg p "to-leaf-$i" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
        GOT=$((GOT+1))
    else
        echo "  leaf-$i: $(echo "$out" | head -c 200)"
    fi
done
if [ "$GOT" = "4" ]; then
    log_pass "all 4 leaves got their own distinct event"
else
    log_fail "only $GOT/4 leaves saw their event"
fi

log_test "no panics/fatals"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Star-5 fan-out summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
