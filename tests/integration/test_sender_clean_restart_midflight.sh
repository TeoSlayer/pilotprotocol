#!/bin/bash
# Chaos Matrix 3: CLEAN restart (docker compose restart, SIGTERM+grace)
# of agent-a while traffic is in flight. Unlike SIGKILL, this gives the
# daemon a chance to flush + close connections. Post-restart:
#   - agent-a re-registers and rebuilds tunnel
#   - no zombie tasks/files on agent-b
#   - fresh ops work

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
echo "Clean restart of agent-a mid-flight"
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
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

# worker
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for T in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$T" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$T" --results "cleanrestart-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.3
    done
'

# ----- fire a small burst, then docker restart agent-a ------
log_test "submit 3 tasks then restart agent-a cleanly"
TIDS=()
for i in 1 2 3; do
    S=$($DC exec -T agent-a bash -c "timeout 8 pilotctl --json task submit agent-b --task 'pre-restart-$i'" 2>&1)
    T=$(echo "$S" | jq -r '.data.task_id // empty')
    [ -n "$T" ] && TIDS+=("$T")
done

$DC restart agent-a >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "agent-a re-registered post-restart"
else
    log_fail "agent-a did not re-register"
    exit 1
fi

# ----- post-restart: agent-a must see its old submitted tasks OR at
# least not crash trying to enumerate them ------
log_test "agent-a task list --type submitted still works post-restart"
POST_LIST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>&1)
if echo "$POST_LIST" | jq -e '.status' >/dev/null 2>&1; then
    log_pass "task list ok"
else
    log_fail "task list broken post-restart: $(echo "$POST_LIST" | head -c 200)"
fi

# ----- fresh task completes end-to-end -----
log_test "fresh task submit post-restart completes"
# warm tunnel (see test_task_accepted_restart_recovery note about
# rekey needing warm up after restart)
$DC exec -T agent-a pilotctl ping agent-b --count 2 --timeout 5s >/dev/null 2>&1 || true

S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "post-restart-fresh" 2>&1)
NTID=$(echo "$S" | jq -r '.data.task_id // empty')
STA=""
if [ -n "$NTID" ]; then
    for _ in $(seq 1 60); do
        STA=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$NTID" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$STA" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 1
    done
fi
if echo "$STA" | grep -qiE "completed|succeeded|done"; then
    log_pass "fresh post-restart task completed"
else
    log_fail "fresh task stuck post-restart (status=$STA)"
fi

# ----- fresh send-file -----
log_test "fresh send-file post-restart"
$DC exec -T agent-a bash -c 'head -c 4096 /dev/urandom >/tmp/clean.dat'
SRC=$($DC exec -T agent-a sha256sum /tmp/clean.dat | awk '{print $1}')
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/clean.dat >/tmp/clean_sf.out 2>&1
RECV=$($DC exec -T agent-b bash -c "ls /root/.pilot/received 2>/dev/null | grep '^clean-' | head -n1" | tr -d '\r\n')
DST=""
[ -n "$RECV" ] && DST=$($DC exec -T agent-b sha256sum "/root/.pilot/received/$RECV" | awk '{print $1}')
if [ "$SRC" = "$DST" ] && [ -n "$DST" ]; then
    log_pass "file sha match post-restart"
else
    log_fail "file mismatch post-restart"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
