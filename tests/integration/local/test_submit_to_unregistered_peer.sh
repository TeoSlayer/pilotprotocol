#!/bin/bash
# Matrix 2 F-series: submit to a hostname the registry has never seen.
#
# Spec requirement: `pilotctl task submit <hostname>` must fail fast
# with a clear error. It must NOT silently queue work, hang
# indefinitely, or corrupt the submitter's local task list.

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
echo "Submit task to unregistered peer"
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
log_pass "agents up"

GHOST="nobody-here-$(date +%s)"

log_test "submit to $GHOST — must fail within 15s"
T0=$(date +%s)
S=$($DC exec -T agent-a bash -c "timeout 15 pilotctl --json task submit $GHOST --task 'to-nobody'" 2>&1)
RC=$?
T1=$(date +%s)
DELTA=$((T1 - T0))

# Accept either: CLI exits non-zero, OR returns status=error, OR
# omits task_id. Anything that IMPLIES success is a bug.
TID=$(echo "$S" | jq -r '.data.task_id // empty' 2>/dev/null)
STATUS=$(echo "$S" | jq -r '.status // empty' 2>/dev/null)
MESSAGE=$(echo "$S" | jq -r '.message // empty' 2>/dev/null)

if [ "$RC" -ne 0 ] || [ "$STATUS" = "error" ] || [ -z "$TID" ]; then
    if [ "$DELTA" -le 15 ]; then
        log_pass "submit rejected in ${DELTA}s (rc=$RC status=$STATUS msg=${MESSAGE:0:80})"
    else
        log_fail "rejection was correct but took ${DELTA}s (should be fast)"
    fi
else
    log_fail "submit claimed success with task_id=$TID for unregistered peer"
fi

# Whatever happened, a's task list must not have a stuck entry
# pointing at the ghost hostname.
log_test "agent-a submitted list not polluted by ghost entry"
LIST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
STUCK=$(echo "$LIST" | jq -r --arg h "$GHOST" '[.data.tasks[]? | select(.target == $h or .recipient == $h)] | length')
if [ "$STUCK" = "0" ] || [ -z "$STUCK" ]; then
    log_pass "no ghost entries in submitted list"
else
    log_fail "$STUCK ghost entries left behind"
fi

log_test "no panic/fatal on agent-a"
BAD=$($DC logs agent-a 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
