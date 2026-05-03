#!/bin/bash
# 5-agent pubsub fan-out: 1 publisher (agent-a), 4 subscribers
# (agent-b,c,d,e). Each subscriber listens on its own topic-alias but all
# are bound to the same topic name. Proves fan-out scales to 4 concurrent
# subscribers without packet drop.

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

DC="docker compose -f docker-compose.multi5.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "5-agent pubsub fan-out"
echo "=========================================="

log_test "Starting 5-agent stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c agent-d agent-e >/dev/null 2>&1
if COUNT=$(wait_all_registered 5 rendezvous); then
    log_pass "5 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

TOPIC="fanout5-$(date +%s)"
PAYLOAD="fanout5-$(date +%s%N)"

log_test "start 4 subscribers (b,c,d,e)"
for s in b c d e; do
    $DC exec -d "agent-$s" bash -c "pilotctl --json subscribe agent-$s $TOPIC --count 1 --timeout 30s > /tmp/sub.log 2>&1"
done
sleep 3
log_pass "subscribers started"

log_test "agent-a publishes to b,c,d,e"
for s in b c d e; do
    $DC exec -T agent-a pilotctl --json publish "agent-$s" "$TOPIC" --data "$PAYLOAD" >/dev/null 2>&1
done
sleep 8

GOT=0
for s in b c d e; do
    out=$($DC exec -T "agent-$s" cat /tmp/sub.log 2>/dev/null)
    if echo "$out" | jq -e --arg p "$PAYLOAD" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
        GOT=$((GOT+1))
    fi
done
if [ "$GOT" = "4" ]; then
    log_pass "all 4 subscribers received event"
else
    log_fail "only $GOT/4 subscribers got it"
    for s in b c d e; do
        echo "  === agent-$s ==="
        $DC exec -T "agent-$s" cat /tmp/sub.log 2>/dev/null | head -c 300 | sed 's/^/    /'
    done
fi

log_test "no panics/fatals in daemon logs"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "5-agent pubsub summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
