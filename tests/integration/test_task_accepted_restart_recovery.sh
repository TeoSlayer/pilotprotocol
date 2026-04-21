#!/bin/bash
# Accepted-task recovery across agent-b daemon restart.
#
# Scenario: submitter a sends T1 to b. A "half-worker" on b accepts
# T1 (task goes ACCEPTED) but *does not* send results. We then
# restart agent-b. After restart, a new worker starts and must be
# able to drive T1 to COMPLETED — whether the task comes back as
# ACCEPTED (and the worker finishes it) or reverts to NEW (and the
# worker re-accepts + completes).
#
# Targets:
#   - in-flight task durability: a task in ACCEPTED state on disk
#     must be reloaded after restart, not dropped
#   - no stuck-ACCEPTED deadlock: if the daemon does not surface
#     ACCEPTED tasks to workers the way it surfaces NEW ones, the
#     test will time out and report the final status
#   - the submitter observes a single authoritative terminal state
#     (no double-completion, no oscillation)

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
echo "Accepted-task restart recovery"
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

# ----- 1. Submit T1 -----------------------------------------------
log_test "submit T1 a->b"
S1=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "half-work-recover" 2>&1)
TID=$(echo "$S1" | jq -r '.data.task_id // empty')
ACC=$(echo "$S1" | jq -r '.data.accepted')
if [ "$ACC" = "true" ] && [ -n "$TID" ]; then
    log_pass "T1 submitted id=$TID"
else
    log_fail "submit failed: $(echo "$S1" | head -c 300)"
    exit 1
fi

# ----- 2. Half-worker: accept only, no send-results ---------------
log_test "half-worker on agent-b accepts T1 without sending results"
$DC exec -T agent-b bash -c "pilotctl task accept --id $TID" >/dev/null 2>&1
sleep 1
PRE=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
if [ "$PRE" = "ACCEPTED" ]; then
    log_pass "pre-restart status=$PRE"
else
    log_fail "pre-restart status=$PRE (want ACCEPTED)"
    exit 1
fi

# Check submitter sees ACCEPTED too (optional — some impls only
# push status on completion).
PRE_SUB=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
echo "    submitter sees pre-restart status=$PRE_SUB"

# ----- 3. Restart agent-b (simulate worker process crash) ---------
log_test "docker compose restart agent-b mid-task"
$DC restart agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "agent-b re-registered"
else
    log_fail "agent-b did not re-register"
    exit 1
fi

# ----- 4. T1 must still be in agent-b's received list -------------
log_test "T1 still visible on agent-b post-restart (status NEW or ACCEPTED)"
POST=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null)
POST_STATUS=$(echo "$POST" | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
HITS=$(echo "$POST" | jq -r --arg t "$TID" '[.data.tasks[]? | select(.task_id == $t)] | length')
if [ "$HITS" = "1" ] && { [ "$POST_STATUS" = "ACCEPTED" ] || [ "$POST_STATUS" = "NEW" ]; }; then
    log_pass "post-restart hits=$HITS status=$POST_STATUS"
else
    log_fail "post-restart hits=$HITS status=$POST_STATUS"
    exit 1
fi

# ----- 5. Start recovery worker; must drive T1 to COMPLETED ------
# Worker warms up the tunnel with a ping first so the tunnel keys are
# fully re-synced before the send-results frames go over the wire.
# Without the ping, the first tasksubmit frames after rekey can be
# silently dropped (see PROBLEM-REGISTRY: restart-tunnel-rekey).
log_test "recovery worker drives T1 to COMPLETED (handles NEW or ACCEPTED)"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    # Warm-up: ensure tunnel to submitter is fully re-keyed.
    pilotctl ping agent-a --count 2 --timeout 3s >>/tmp/worker.log 2>&1 || true
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\" or .status == \"ACCEPTED\") | .task_id"); do
            ST=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .status")
            if [ "$ST" = "NEW" ]; then
                pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            fi
            pilotctl task send-results --id "$TID" --results "recovered-after-restart" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.3
    done
'

FINAL=""
for _ in $(seq 1 60); do
    FINAL=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
    log_pass "submitter final status=$FINAL"
else
    log_fail "T1 did not reach completion after restart (status=$FINAL)"
    $DC exec -T agent-b bash -c 'cat /tmp/worker.log 2>/dev/null | tail -20' | sed 's/^/    /'
fi

# ----- 6. Result payload landed ----------------------------------
log_test "agent-a has the 'recovered-after-restart' result for T1"
RES=$($DC exec -T agent-a pilotctl --json task result --id "$TID" 2>/dev/null)
RT=$(echo "$RES" | jq -r '.data.content // empty' | head -c 200)
if echo "$RT" | grep -q "recovered-after-restart"; then
    log_pass "result text: $RT"
else
    log_fail "unexpected result: $(echo "$RES" | head -c 300)"
fi

# ----- 7. Exactly one completed record on submitter side ---------
log_test "exactly one submitted record for T1 (no double completion)"
LIST_A=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
N=$(echo "$LIST_A" | jq -r --arg t "$TID" '[.data.tasks[]? | select(.task_id == $t)] | length')
if [ "$N" = "1" ]; then
    log_pass "submitted records=$N"
else
    log_fail "submitted records=$N (want 1)"
fi

# ----- 8. No panic/fatal in daemon logs --------------------------
log_test "no panics/fatals in daemon logs"
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
echo "Accepted-task restart recovery summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
