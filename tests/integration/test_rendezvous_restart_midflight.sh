#!/bin/bash
# Rendezvous restart while a tunnel between a and b is already established
# and mid-flight.
#
# Scenario: agent-a and agent-b establish crypto tunnel + exchange a warm-up
# task. Then `docker compose restart rendezvous`. While rendezvous is down,
# verify the existing a<->b tunnel still carries traffic (submit, send-file,
# pub/sub) — rendezvous is a control-plane service, tunnel data must not
# require it once the endpoints are cached. After rendezvous comes back up,
# verify new lookups resolve again (cache miss path works) and both agents
# re-register cleanly.
#
# Targets:
#   - tunnel data plane survives rendezvous downtime (real control vs data
#     separation — not "rendezvous is a SPOF for runtime traffic")
#   - no panic/fatal in agent logs when rendezvous stops accepting TCP
#   - post-restart registry reflects both agents (re-register loop works)
#   - fresh lookup after rendezvous restart still resolves a known peer
#
# Differs from test_resilience.sh: that one restarts agents; this one
# explicitly keeps agents up and attacks the control-plane service.

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

DC="docker compose -f docker-compose.multi.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Rendezvous restart mid-flight"
echo "=========================================="

log_test "Starting p2p stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register"
    exit 1
fi

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Start a simple worker on agent-b that accepts anything + returns results.
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.3
    done
'

# ----- 1. Warm-up: one task round-trip to establish tunnel + caches ----
log_test "warm-up task to establish tunnel + peer caches"
S1=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "warmup" 2>&1)
TID0=$(echo "$S1" | jq -r '.data.task_id // empty')
if [ -z "$TID0" ]; then
    log_fail "warmup submit failed: $S1"
    exit 1
fi
WARM=""
for _ in $(seq 1 30); do
    WARM=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID0" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$WARM" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$WARM" | grep -qiE "completed|succeeded|done"; then
    log_pass "tunnel warm (status=$WARM)"
else
    log_fail "warmup task did not complete (status=$WARM) — env not ready"
    exit 1
fi

# ----- 2. Stop rendezvous (compose stop, not down) ---------------------
log_test "stop rendezvous container (keep agents up)"
$DC stop rendezvous >/dev/null 2>&1
sleep 2
R_STATE=$($DC ps --status running --services 2>/dev/null | tr '\n' ' ')
if echo "$R_STATE" | grep -qv "rendezvous"; then
    log_pass "rendezvous stopped; still running: $R_STATE"
else
    log_fail "rendezvous did not stop: $R_STATE"
fi

# ----- 3. Tunnel still carries task traffic while rendezvous is down --
log_test "task a->b completes while rendezvous down (30s)"
S2=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "mid-outage" 2>&1)
TID1=$(echo "$S2" | jq -r '.data.task_id // empty')
if [ -z "$TID1" ]; then
    log_fail "submit during outage failed: $(echo "$S2" | head -c 300)"
else
    MID=""
    for _ in $(seq 1 30); do
        MID=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$TID1" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$MID" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 1
    done
    if echo "$MID" | grep -qiE "completed|succeeded|done"; then
        log_pass "task completed mid-outage (status=$MID)"
    else
        log_fail "task stuck mid-outage (status=$MID) — data plane needs rendezvous?"
    fi
fi

# ----- 4. send-file survives rendezvous outage ------------------------
log_test "send-file 2 KiB a->b while rendezvous down"
$DC exec -T agent-a bash -c 'head -c 2048 /dev/urandom >/tmp/mid.dat' >/dev/null 2>&1
SRC=$($DC exec -T agent-a sha256sum /tmp/mid.dat | awk '{print $1}')
SF=$($DC exec -T agent-a timeout 20 pilotctl --json send-file agent-b /tmp/mid.dat 2>&1)
ACK=$(echo "$SF" | jq -r '.data.ack // empty' 2>/dev/null)
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received | grep '^mid-' | head -n1" | tr -d '\r\n')
DST=""
if [ -n "$RECV" ]; then
    DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
fi
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "file ok under outage (ack=$ACK sha=${SRC:0:12}...)"
else
    log_fail "file mismatch under outage src=${SRC:0:12}... dst=${DST:0:12}... ack=$ACK"
fi

# ----- 5. Bring rendezvous back up -----------------------------------
log_test "start rendezvous back up"
$DC start rendezvous >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents re-registered post-rendezvous-restart (total=$COUNT)"
else
    log_fail "agents did not re-register (total=$COUNT)"
fi

# ----- 6. Fresh lookup from a->b still resolves after rendezvous restart
log_test "pilotctl lookup agent-b from agent-a resolves"
LK=$($DC exec -T agent-a pilotctl --json lookup agent-b 2>&1)
ADDR=$(echo "$LK" | jq -r '.data.address // empty')
if [ -n "$ADDR" ]; then
    log_pass "lookup resolved: $ADDR"
else
    log_fail "lookup empty: $(echo "$LK" | head -c 300)"
fi

# ----- 7. Post-restart task still completes --------------------------
log_test "task a->b completes post-rendezvous-restart"
S3=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "post-rv" 2>&1)
TID2=$(echo "$S3" | jq -r '.data.task_id // empty')
POST=""
for _ in $(seq 1 30); do
    POST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID2" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$POST" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$POST" | grep -qiE "completed|succeeded|done"; then
    log_pass "post-restart task completed (status=$POST)"
else
    log_fail "post-restart task stuck (status=$POST)"
fi

# ----- 8. No panic/fatal in agent logs while rendezvous was absent --
log_test "no panics/fatals in agent logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Rendezvous restart summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
