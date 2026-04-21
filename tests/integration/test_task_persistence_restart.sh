#!/bin/bash
# Task persistence across agent-b daemon restart.
#
# Scenario: submitter a sends T1 to worker-less b. T1 sits as NEW in
# ~/.pilot/tasks/received/ on agent-b. Restart agent-b in place
# (`docker compose restart` — container preserved, so the identity
# at /root/.pilot/identity.json and the task file both survive).
# After re-registration, start a worker on b and drive T1 to
# completion. Verify submitter on a sees the completed state.
#
# Targets:
#   - task store durability: tasks/received/<id>.json must reload
#     on startup so the worker still sees it
#   - identity persistence: agent-b's node_id must be stable so the
#     registry entry re-binds to the same address a already used
#   - cross-restart result delivery: when b finally completes T1,
#     the result message must reach a even though a's tunnel to b
#     had its endpoint drop and re-add
#   - no duplicate-task hazard: after restart, T1 must appear
#     exactly once in b's received list (not 0, not 2)

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
echo "Task persistence across daemon restart"
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

# ----- 1. Capture agent-b public_key for later cross-restart check -
# identity.json holds the durable crypto identity; node_id is derived
# from that and re-issued by the rendezvous on each registration.
PK_BEFORE=$($DC exec -T agent-b bash -c 'cat /root/.pilot/identity.json' 2>/dev/null | jq -r '.public_key // empty')
if [ -n "$PK_BEFORE" ]; then
    log_pass "agent-b public_key before: ${PK_BEFORE:0:16}..."
else
    log_fail "could not read agent-b identity"
    exit 1
fi

# ----- 2. Submit T1 a -> b (no worker yet) ------------------------
log_test "submit T1 a->b; expect NEW status, no auto-accept"
S1=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "survive-restart" 2>&1)
TID=$(echo "$S1" | jq -r '.data.task_id // empty')
ACC=$(echo "$S1" | jq -r '.data.accepted')
if [ "$ACC" = "true" ] && [ -n "$TID" ]; then
    log_pass "T1 accepted, id=$TID"
else
    log_fail "T1 submit failed: $(echo "$S1" | head -c 300)"
    exit 1
fi

sleep 1
log_test "T1 is NEW on agent-b before restart"
PRE=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
if [ "$PRE" = "NEW" ]; then
    log_pass "pre-restart status=$PRE"
else
    log_fail "pre-restart status=$PRE (want NEW)"
    exit 1
fi

# ----- 3. Restart agent-b (container preserved) -------------------
log_test "docker compose restart agent-b"
$DC restart agent-b >/dev/null 2>&1

# Wait for daemon + registration
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "agent-b re-registered (total_nodes=$COUNT)"
else
    log_fail "agent-b did not re-register (total_nodes=$COUNT)"
    exit 1
fi

# ----- 4. Identity must be identical across restart ---------------
log_test "agent-b public_key is stable across restart"
PK_AFTER=$($DC exec -T agent-b bash -c 'cat /root/.pilot/identity.json' 2>/dev/null | jq -r '.public_key // empty')
if [ "$PK_BEFORE" = "$PK_AFTER" ]; then
    log_pass "identity stable: ${PK_AFTER:0:16}..."
else
    log_fail "identity drift: before=${PK_BEFORE:0:16}... after=${PK_AFTER:0:16}..."
fi

# ----- 5. T1 still visible, still NEW, exactly once ---------------
log_test "T1 still visible as NEW on agent-b post-restart, exactly once"
POST=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null)
HITS=$(echo "$POST" | jq -r --arg t "$TID" '[.data.tasks[]? | select(.task_id == $t)] | length')
STATUS=$(echo "$POST" | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status' | head -n1)
if [ "$HITS" = "1" ] && [ "$STATUS" = "NEW" ]; then
    log_pass "post-restart hits=$HITS status=$STATUS"
else
    log_fail "post-restart hits=$HITS status=$STATUS"
fi

# ----- 6. Start worker on agent-b; expect completion --------------
log_test "start worker on agent-b; drive T1 to completion"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "survived-restart" >>/tmp/worker.log 2>&1 || true
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
    log_pass "submitter sees final status=$FINAL"
else
    log_fail "T1 not completed after worker started (submitter status=$FINAL)"
    $DC exec -T agent-b bash -c 'cat /tmp/worker.log 2>/dev/null | tail -20' | sed 's/^/    /'
fi

# ----- 7. Result payload lands on agent-a -------------------------
log_test "agent-a has the 'survived-restart' result for T1"
RES=$($DC exec -T agent-a pilotctl --json task result --id "$TID" 2>/dev/null)
RT=$(echo "$RES" | jq -r '.data.content // .data.results // .data.result_text // empty' | head -c 200)
if echo "$RT" | grep -q "survived-restart"; then
    log_pass "result text: $RT"
else
    log_fail "unexpected result: $(echo "$RES" | head -c 300)"
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
echo "Task persistence summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
