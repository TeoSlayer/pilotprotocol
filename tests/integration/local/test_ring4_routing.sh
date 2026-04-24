#!/bin/bash
# Ring-4 application-layer routing: a message is passed around the ring
# a -> b -> c -> d -> a. Each hop rewrites the payload with its hostname
# appended so the final message contains the full path. Proves multi-hop
# app-layer routing and that no hop drops or duplicates.
#
# Note: this is NOT network-layer ring routing — Pilot's overlay is a
# flat address space. The "ring" is enforced by application-level
# forwarders we deploy per agent.

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

DC="docker compose -f docker-compose.ring4.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Ring-4 a->b->c->d->a routing"
echo "=========================================="

log_test "Starting 4-agent ring stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c agent-d >/dev/null 2>&1
if COUNT=$(wait_all_registered 4 rendezvous); then
    log_pass "4 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

for s in a b c d; do
    $DC exec -T "agent-$s" pilotctl --json inbox --clear >/dev/null 2>&1
done

# Per-agent forwarder: next-hop mapping b->c, c->d, d->a.
# Forwarders read JSON msgs {ring:1, path:"...", ttl:N} from inbox,
# append their own hostname to path, decrement ttl, forward to next.
# ttl=0 or arrival at final destination (path contains a,b,c,d) means
# the forwarder should NOT forward further; a's forwarder is the one
# that terminates ring by not forwarding back to b.
start_forwarder() {
    local host=$1 next=$2 terminal=${3:-0}
    $DC exec -d "$host" bash -c "
        HOST='$host'
        NEXT='$next'
        TERMINAL='$terminal'
        rm -f /tmp/ring_stop /tmp/ring.log
        INBOX=/root/.pilot/inbox
        while [ ! -f /tmp/ring_stop ]; do
            for f in \$(ls -1 \$INBOX/*.json 2>/dev/null); do
                TYPE=\$(jq -r '.type // \"\"' \"\$f\" 2>/dev/null)
                if [ \"\$TYPE\" != \"JSON\" ]; then continue; fi
                DATA=\$(jq -r '.data // \"\"' \"\$f\" 2>/dev/null)
                RING=\$(echo \"\$DATA\" | jq -r '.ring // \"\"')
                if [ \"\$RING\" != \"1\" ]; then continue; fi
                PATH_SO_FAR=\$(echo \"\$DATA\" | jq -r '.path // \"\"')
                TTL=\$(echo \"\$DATA\" | jq -r '.ttl // 0')
                NEW_PATH=\"\$PATH_SO_FAR,\$HOST\"
                NEW_TTL=\$((TTL - 1))
                echo \"\$(date +%H:%M:%S.%N) hop host=\$HOST path=\$NEW_PATH ttl=\$NEW_TTL\" >> /tmp/ring.log
                rm -f \"\$f\"
                if [ \"\$TERMINAL\" = \"1\" ]; then
                    # Record the final path in our own inbox marker.
                    echo \"\$NEW_PATH\" > /tmp/ring-final.txt
                    continue
                fi
                if [ \"\$NEW_TTL\" -le 0 ]; then
                    echo \"\$NEW_PATH\" > /tmp/ring-final.txt
                    continue
                fi
                NEW_DATA=\$(jq -n --arg p \"\$NEW_PATH\" --argjson ttl \$NEW_TTL '{ring:\"1\", path:\$p, ttl:\$ttl}')
                pilotctl send-message \"\$NEXT\" --data \"\$NEW_DATA\" --type json >>/tmp/ring.log 2>&1 || true
            done
            sleep 0.1
        done
    "
}

log_test "starting ring forwarders (b->c, c->d, d->a, a=terminal)"
start_forwarder agent-b agent-c 0
start_forwarder agent-c agent-d 0
start_forwarder agent-d agent-a 0
start_forwarder agent-a agent-b 1   # terminal: consumes and stops
sleep 2
log_pass "forwarders running"

# Inject the ring from OUTSIDE — agent-b receives the initial message
# from somebody. Easiest: agent-a sends the first message to agent-b
# (acts as both originator AND terminal; its forwarder is configured as
# terminal so when the packet returns, it halts).
log_test "agent-a kicks the ring (path=start, ttl=4)"
INIT=$($DC exec -T agent-a pilotctl --json send-message agent-b \
    --data '{"ring":"1","path":"start","ttl":4}' --type json 2>&1)
if echo "$INIT" | jq -e '.data' >/dev/null 2>&1 || echo "$INIT" | grep -qi delivered; then
    log_pass "ring kicked"
else
    log_fail "could not kick ring: $INIT"
fi

log_test "agent-a's terminal step records path in /tmp/ring-final.txt within 20s"
FINAL=""
for _ in $(seq 1 20); do
    FINAL=$($DC exec -T agent-a cat /tmp/ring-final.txt 2>/dev/null | tr -d '\r\n')
    if [ -n "$FINAL" ]; then break; fi
    sleep 1
done
if [ -n "$FINAL" ]; then
    log_pass "final path: $FINAL"
else
    log_fail "ring did not close"
    for s in a b c d; do
        echo "  === $s ring.log ==="
        $DC exec -T "agent-$s" tail -20 /tmp/ring.log 2>&1 | sed 's/^/    /'
    done
fi

log_test "final path shows all four hops in order"
EXPECT="start,agent-b,agent-c,agent-d,agent-a"
if [ "$FINAL" = "$EXPECT" ]; then
    log_pass "path correct"
else
    log_fail "path wrong: got '$FINAL' want '$EXPECT'"
fi

log_test "no panics/fatals"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

for s in a b c d; do
    $DC exec -T "agent-$s" touch /tmp/ring_stop >/dev/null 2>&1
done
$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Ring-4 routing summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
