#!/bin/bash
# Polo persistence: scores survive a registry restart.
#
# Polo is private — clients cannot read scores directly. So we verify
# persistence through the polo gate's observable behavior:
#   1. Fresh stack — a.polo == b.polo == 0. Task a->b is allowed.
#   2. Submit + complete T1 a->b. This bumps b.polo positive and
#      a.polo negative (per polo math). Now a.polo < b.polo.
#   3. Attempt T2 a->b — must be REJECTED by the polo gate.
#   4. `docker compose restart rendezvous`.
#   5. Attempt T3 a->b — must STILL be REJECTED. If polo wasn't
#      persisted across the restart both scores would reset to 0
#      and T3 would slip through, proving the regression.

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
echo "Polo gate persistence across rendezvous restart"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1 || true
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
log_pass "agents up"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Auto-accept worker on b
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "polo-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.25
    done
'

# Phase 1: fresh state — T1 must succeed (both polo == 0).
log_test "T1 a->b succeeds (fresh polo == 0 == 0)"
S1=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "polo-pre" 2>&1)
TID1=$(echo "$S1" | jq -r '.data.task_id // empty')
ACC1=$(echo "$S1" | jq -r '.data.accepted')
[ "$ACC1" = "true" ] && [ -n "$TID1" ] && log_pass "T1 accepted" || { log_fail "T1 rejected at fresh state: $S1"; exit 1; }

# Wait for T1 to complete so polo deltas land on the registry.
for _ in $(seq 1 45); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID1" '.data.tasks[]? | select(.task_id == $t) | .status')
    echo "$ST" | grep -qiE "completed|succeeded|done" && break
    sleep 1
done
echo "$ST" | grep -qiE "completed|succeeded|done" || { log_fail "T1 never completed"; exit 1; }
log_pass "T1 completed — polo mutated"

# Wait for the registry's saveLoop to flush (1s ticker).
sleep 2

# Phase 2: T2 must be rejected — submitter polo now below receiver polo.
log_test "T2 a->b rejected by polo gate (pre-restart)"
S2=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "polo-pre-2" 2>&1)
ACC2=$(echo "$S2" | jq -r '.data.accepted')
[ "$ACC2" = "false" ] && log_pass "T2 rejected as expected" || log_fail "T2 unexpectedly landed: $S2"

# Phase 3: restart rendezvous — polo must persist via -store flag.
log_test "restart rendezvous service"
$DC restart rendezvous >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "rendezvous back, $COUNT agents visible" || { log_fail "rendezvous did not come back"; exit 1; }

# Phase 4: T3 must STILL be rejected — proves polo state survived restart.
log_test "T3 a->b still rejected after restart (polo state preserved)"
S3=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "polo-post" 2>&1)
ACC3=$(echo "$S3" | jq -r '.data.accepted')
if [ "$ACC3" = "false" ]; then
    log_pass "polo persistence verified — T3 still rejected"
else
    log_fail "polo state LOST across restart — T3 slipped through: $S3"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
