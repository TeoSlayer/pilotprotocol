#!/bin/bash
# Chaos Matrix 3: restart beacon/rendezvous (same container) mid-flight.
# Beacon is port 9001 of the rendezvous container; it drives hole-punch
# and relay. Restart simulates operational maintenance.
#
# Agents must:
#   - survive the beacon outage (existing tunnels keep working)
#   - NOT panic when beacon TCP/UDP endpoints disappear
#   - resume beacon-assisted ops (e.g. re-discover) after beacon back up
#
# Differs from test_rendezvous_restart_midflight.sh — that test stops
# the whole rendezvous container (beacon AND registry). Here we want to
# simulate "only the beacon is sick, registry HTTP still answers" but
# because they are in the same container today, we treat a container
# restart as the best available approximation and document that
# ambiguity.

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

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.chaos.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Beacon restart mid-flight"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for T in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$T" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$T" --results "beacon-restart-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.3
    done
'

# Warm the tunnel before the restart so data-plane is cached.
log_test "warm task before beacon restart"
S0=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "warm" 2>&1)
T0=$(echo "$S0" | jq -r '.data.task_id // empty')
WS=""
if [ -n "$T0" ]; then
    for _ in $(seq 1 30); do
        WS=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$T0" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$WS" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 1
    done
fi
echo "$WS" | grep -qiE "completed|succeeded|done" && log_pass "warm ok" || { log_fail "warm failed $WS"; exit 1; }

# ----- Restart beacon container ---------------------
log_test "docker compose restart rendezvous (beacon container)"
$DC restart rendezvous >/dev/null 2>&1

# Give the container a moment to come back.
for _ in $(seq 1 60); do
    if $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats >/dev/null 2>&1; then break; fi
    sleep 1
done
if $DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats >/dev/null 2>&1; then
    log_pass "rendezvous+beacon container back online"
else
    log_fail "rendezvous did not come back"
    exit 1
fi

# ----- Both agents must re-register -----
log_test "both agents re-register post-beacon-restart"
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "total_nodes=$COUNT" || log_fail "only $COUNT agents after beacon restart"

# Rebalance polo: the warm task pushed a below b. Run one b->a round
# trip so a<->b are at parity before the post-restart submit — the
# polo gate would otherwise reject a->b.
$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
$DC exec -d agent-a bash -c '
    rm -f /tmp/aw_stop /tmp/aw.log
    while [ ! -f /tmp/aw_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for T in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$T" >>/tmp/aw.log 2>&1 || true
            pilotctl task send-results --id "$T" --results "rebal-ok" >>/tmp/aw.log 2>&1 || true
        done
        sleep 0.3
    done
'
sleep 1
$DC exec -T agent-b pilotctl --json task submit agent-a --task "rebal-b2a" >/dev/null 2>&1 || true
sleep 3
$DC exec -T agent-a touch /tmp/aw_stop >/dev/null 2>&1

# ----- Existing tunnel traffic still flows ----
log_test "task still completes post-beacon-restart"
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "post-beacon" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
STA=""
if [ -n "$TID" ]; then
    for _ in $(seq 1 60); do
        STA=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$STA" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 1
    done
fi
if echo "$STA" | grep -qiE "completed|succeeded|done"; then
    log_pass "post-beacon task completed"
else
    log_fail "post-beacon task stuck (status=$STA)"
fi

# ----- fresh lookup still works (beacon-assisted discovery) ----
log_test "pilotctl lookup works post-beacon-restart"
LK=$($DC exec -T agent-a pilotctl --json find agent-b 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -n "$ADDR" ]; then
    log_pass "lookup ok: $ADDR"
else
    log_fail "lookup empty: $(echo "$LK" | head -c 300)"
fi

log_test "no panic/fatal in agent logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
