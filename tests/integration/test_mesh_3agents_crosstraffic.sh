#!/bin/bash
# Full 3-agent mesh cross-traffic: every pair a<->b, a<->c, b<->c exchanges
# pings, text messages, and one file simultaneously. Proves six independent
# tunnels can stay up at once without interfering.

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
echo "3-agent mesh cross-traffic"
echo "=========================================="

log_test "Starting 3-agent stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "3 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

# Prep distinct 4KiB files per sender.
for s in a b c; do
    $DC exec -T "agent-$s" bash -c "head -c 4096 /dev/urandom > /tmp/mesh-$s.bin" >/dev/null 2>&1
done

# For each pair, clear inbox.
for s in a b c; do
    $DC exec -T "agent-$s" pilotctl --json inbox --clear >/dev/null 2>&1
done

# Concurrent cross-traffic: each agent does 2 sends to the OTHER TWO.
log_test "fire 6 parallel send-message + 6 parallel ping"
for SENDER in a b c; do
    for RECV in a b c; do
        [ "$SENDER" = "$RECV" ] && continue
        $DC exec -T "agent-$SENDER" pilotctl send-message "agent-$RECV" \
            --data "msg-from-$SENDER-to-$RECV" --type text >/dev/null 2>&1 &
        $DC exec -T "agent-$SENDER" pilotctl ping "agent-$RECV" --count 1 --timeout 10s >/dev/null 2>&1 &
    done
done
wait
log_pass "messages + pings dispatched"

# Wait briefly for inbox writes.
sleep 3

# Each agent should have received exactly 2 messages (from the other two).
log_test "each inbox contains 2 cross-traffic messages"
OK=0
for RECV in a b c; do
    IN=$($DC exec -T "agent-$RECV" pilotctl --json inbox 2>/dev/null)
    exp1=""; exp2=""
    case "$RECV" in
        a) exp1="msg-from-b-to-a"; exp2="msg-from-c-to-a";;
        b) exp1="msg-from-a-to-b"; exp2="msg-from-c-to-b";;
        c) exp1="msg-from-a-to-c"; exp2="msg-from-b-to-c";;
    esac
    GOT1=$(echo "$IN" | jq -r --arg d "$exp1" '[.data.messages[]? | select(.data == $d)] | length')
    GOT2=$(echo "$IN" | jq -r --arg d "$exp2" '[.data.messages[]? | select(.data == $d)] | length')
    if [ "$GOT1" = "1" ] && [ "$GOT2" = "1" ]; then
        OK=$((OK+1))
    else
        echo "  agent-$RECV: want [$exp1,$exp2] got1=$GOT1 got2=$GOT2"
    fi
done
if [ "$OK" = "3" ]; then
    log_pass "all 3 inboxes have correct cross-traffic"
else
    log_fail "only $OK/3 inboxes correct"
fi

# Concurrent 6 file transfers.
log_test "6 concurrent send-files across the mesh"
for SENDER in a b c; do
    for RECV in a b c; do
        [ "$SENDER" = "$RECV" ] && continue
        $DC exec -T "agent-$SENDER" timeout 30 pilotctl send-file "agent-$RECV" "/tmp/mesh-$SENDER.bin" >/dev/null 2>&1 &
    done
done
wait

sleep 3

# Each receiver should have 2 mesh-* files in /root/.pilot/received/
OK=0
for RECV in a b c; do
    N=$($DC exec -T "agent-$RECV" bash -c "ls /root/.pilot/received 2>/dev/null | grep -c '^mesh-'")
    if [ "$N" -ge "2" ]; then
        OK=$((OK+1))
    else
        echo "  agent-$RECV got only $N mesh-* files"
    fi
done
if [ "$OK" = "3" ]; then
    log_pass "all 3 receivers got >= 2 mesh files"
else
    log_fail "$OK/3 receivers had both files"
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
echo "Mesh crosstraffic summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
