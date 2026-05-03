#!/bin/bash
# Chaos Matrix 3: SIGKILL agent-b AFTER the task is ACCEPTED but BEFORE
# send-results. Submitter (agent-a) must eventually see the task in a
# terminal non-success state (FAILED / EXPIRED / aborted) — it must NOT
# stay "stuck" in ACCEPTED forever, and must NOT be falsely marked
# COMPLETED.

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
echo "SIGKILL agent-b between ACCEPTED and results"
echo "=========================================="

cleanup() { $DC down -v >/dev/null 2>&1; }
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

# ----- submit T1 -----
log_test "submit task a->b"
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "kill-after-accept" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
[ -z "$TID" ] && { log_fail "submit failed"; exit 1; }
log_pass "submitted id=$TID"

# ----- half-worker: accept only, no send-results -----
log_test "agent-b accepts (but not sends results)"
$DC exec -T agent-b pilotctl task accept --id "$TID" >/dev/null 2>&1
sleep 1
PRE=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
[ "$PRE" = "ACCEPTED" ] && log_pass "status=ACCEPTED on b" || { log_fail "status=$PRE"; exit 1; }

# ----- SIGKILL agent-b -----
log_test "SIGKILL agent-b"
$DC kill agent-b >/dev/null 2>&1
sleep 1
if $DC ps --status running --services 2>/dev/null | grep -q "^agent-b$"; then
    log_fail "agent-b still up"
    exit 1
fi
log_pass "agent-b dead"

# ----- Submitter must NOT be stuck; must NOT show completed ----
# We give it up to 120s to recognize the dead worker. Spec says:
#   terminal non-success state acceptable: FAILED, EXPIRED, ABORTED,
#   TIMEOUT, CANCELLED, CANCELED — anything not {NEW, ACCEPTED,
#   IN_PROGRESS, RUNNING, PENDING, COMPLETED, SUCCEEDED, DONE}
log_test "submitter observes task not stuck and not falsely completed (120s)"
FINAL=""
for _ in $(seq 1 120); do
    FINAL=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    # exit if terminal
    if echo "$FINAL" | grep -qiE "failed|expired|aborted|timeout|timed_?out|cancell?ed|rejected"; then
        break
    fi
    if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
        break
    fi
    sleep 1
done

if echo "$FINAL" | grep -qiE "completed|succeeded|done"; then
    log_fail "submitter FALSELY saw completed after worker died: status=$FINAL"
elif echo "$FINAL" | grep -qiE "failed|expired|aborted|timeout|timed_?out|cancell?ed|rejected"; then
    log_pass "submitter observed terminal failure status=$FINAL"
else
    # Still ACCEPTED/PENDING after 120s — that is "stuck". Known risk.
    log_fail "submitter stuck at status=$FINAL after 120s — no failure detection"
fi

# ----- submitter daemon is responsive -----
log_test "agent-a daemon still responsive"
if $DC exec -T agent-a pilotctl daemon status --check >/dev/null 2>&1; then
    log_pass "daemon responsive"
else
    log_fail "agent-a hung"
fi

# ----- no panic on agent-a -----
log_test "no panic/fatal on agent-a"
BAD=$($DC logs agent-a 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
