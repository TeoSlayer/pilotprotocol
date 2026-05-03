#!/bin/bash
# Three-agent message-forwarding chain.
# a sends a JSON message to b tagged {hop:1, payload:X, to:"agent-c"}.
# b has a forwarder that unwraps messages with to:"agent-c" and
# re-sends them as text "final:X" to agent-c.
# a then polls agent-c's inbox via agent-c directly and asserts "final:X"
# arrived.
#
# Proves ordered, multi-hop message delivery using the dataexchange service.

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
echo "Chain a->b->c message forwarding"
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

# Clear inboxes.
for s in agent-a agent-b agent-c; do
    $DC exec -T $s pilotctl --json inbox --clear >/dev/null 2>&1
done

# ----- Forwarder on agent-b: watches inbox for {to:"agent-c"} JSON ----
log_test "start forwarder on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/fwd_stop /tmp/fwd.log
    INBOX=/root/.pilot/inbox
    while [ ! -f /tmp/fwd_stop ]; do
        for f in $(ls -1 $INBOX/*.json 2>/dev/null); do
            TYPE=$(jq -r ".type // \"\"" "$f" 2>/dev/null)
            if [ "$TYPE" != "JSON" ]; then continue; fi
            DATA=$(jq -r ".data // \"\"" "$f" 2>/dev/null)
            TO=$(echo "$DATA" | jq -r ".to // \"\"" 2>/dev/null)
            P=$(echo "$DATA" | jq -r ".payload // \"\"" 2>/dev/null)
            if [ "$TO" != "agent-c" ] || [ -z "$P" ]; then continue; fi
            echo "$(date +%H:%M:%S.%N) forward payload=$P" >> /tmp/fwd.log
            pilotctl send-message agent-c --data "final:$P" --type text >>/tmp/fwd.log 2>&1 || true
            rm -f "$f"
        done
        sleep 0.1
    done
    echo forwarder-exit >> /tmp/fwd.log
'
sleep 1
log_pass "forwarder running"

# ----- agent-a sends the chain trigger ---------------------------------
log_test "agent-a sends JSON {to:\"agent-c\", payload:\"hello-chain\"} to agent-b"
SEND=$($DC exec -T agent-a pilotctl --json send-message agent-b \
    --data '{"to":"agent-c","payload":"hello-chain"}' --type json 2>&1)
OK=$(echo "$SEND" | jq -r '.data.ack // empty')
if [ -n "$OK" ] || echo "$SEND" | grep -qi "delivered"; then
    log_pass "trigger sent"
else
    log_fail "trigger failed: $SEND"
fi

# ----- agent-c sees final:hello-chain in its inbox ---------------------
log_test "agent-c inbox gets text 'final:hello-chain' within 20s"
FOUND=""
for _ in $(seq 1 20); do
    IN=$($DC exec -T agent-c pilotctl --json inbox 2>/dev/null)
    FOUND=$(echo "$IN" | jq -r '[.data.messages[]? | select(.data == "final:hello-chain")] | length' 2>/dev/null)
    if [ "$FOUND" = "1" ]; then break; fi
    sleep 1
done
if [ "$FOUND" = "1" ]; then
    log_pass "chain delivered: final:hello-chain on agent-c"
else
    log_fail "chain not delivered (matches=$FOUND)"
    $DC exec -T agent-b tail -30 /tmp/fwd.log 2>&1 | sed 's/^/  b-fwd: /'
    $DC exec -T agent-c pilotctl --json inbox 2>&1 | head -c 500
fi

# ----- agent-a's inbox did NOT receive the wrapped payload -------------
log_test "agent-a inbox did not receive the chain output"
A_IN=$($DC exec -T agent-a pilotctl --json inbox 2>/dev/null)
LOOP=$(echo "$A_IN" | jq -r '[.data.messages[]? | select(.data == "final:hello-chain")] | length' 2>/dev/null)
if [ "$LOOP" = "0" ]; then
    log_pass "agent-a inbox is unaffected"
else
    log_fail "agent-a saw chain output (should have gone only to c)"
fi

# ----- Clean logs -------
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b agent-c 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

# Cleanup
$DC exec -T agent-b touch /tmp/fwd_stop >/dev/null 2>&1
$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Chain message test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
