#!/bin/bash
# 3-agent fan-out via pubsub: agent-a publishes on a topic hosted by
# agent-b and agent-c simultaneously; both subscribers on b and c
# must receive the event.
#
# Proves one publisher can push to multiple independent receivers'
# topics in quick succession without losing events.

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

DC="docker compose -f docker-compose.multi3.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "3-agent pubsub fan-out"
echo "=========================================="

log_test "Starting 3-agent stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "all 3 agents registered (total_nodes=$COUNT)"
else
    log_fail "agents did not register (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

TOPIC="fanout3-$(date +%s)"
PAYLOAD="fanout3-$(date +%s%N)"

log_test "subscribe on agent-b and agent-c (topic=$TOPIC)"
$DC exec -d agent-b bash -c "pilotctl --json subscribe agent-b $TOPIC --count 1 --timeout 25s > /tmp/sub_b.log 2>&1"
$DC exec -d agent-c bash -c "pilotctl --json subscribe agent-c $TOPIC --count 1 --timeout 25s > /tmp/sub_c.log 2>&1"
sleep 2
log_pass "subscribers started"

log_test "agent-a publishes to b and c"
$DC exec -T agent-a pilotctl --json publish agent-b "$TOPIC" --data "$PAYLOAD" >/dev/null 2>&1
$DC exec -T agent-a pilotctl --json publish agent-c "$TOPIC" --data "$PAYLOAD" >/dev/null 2>&1
sleep 6

GOT=0
for who in b c; do
    svc="agent-$who"
    out=$($DC exec -T "$svc" cat /tmp/sub_${who}.log 2>/dev/null)
    if echo "$out" | jq -e --arg p "$PAYLOAD" '.data.events[]? | select(.data == $p)' >/dev/null 2>&1; then
        GOT=$((GOT+1))
    else
        log_test "  debug $svc log:"
        echo "$out" | head -c 400 | sed 's/^/    /'
    fi
done
if [ "$GOT" = "2" ]; then
    log_pass "both b and c received the event"
else
    log_fail "only $GOT/2 subscribers got the event"
fi

log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b agent-c 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "3-agent fanout pubsub summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
