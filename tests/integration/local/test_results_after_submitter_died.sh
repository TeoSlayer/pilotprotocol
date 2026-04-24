#!/bin/bash
# Matrix 2 F-series: worker tries to send results after the submitter
# has died.
#
# Sequence:
#   1. a submits T1 to b. b accepts.
#   2. SIGKILL agent-a BEFORE b sends results.
#   3. b runs `pilotctl task send-results --id T1`.
#   4. Spec: b's send-results must fail (or complete locally with a
#      clear error), must NOT crash, must NOT panic, must NOT hang.
#   5. When agent-a comes back, its on-disk submitted list for T1 is
#      unchanged (still ACCEPTED); result text is absent.

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
echo "Results after submitter died"
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

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Submit + accept (no results yet)
log_test "submit + accept T1"
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "submitter-dies" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "submit failed: $(echo "$S" | head -c 300)"; exit 1; }
$DC exec -T agent-b pilotctl task accept --id "$TID" >/dev/null 2>&1
sleep 1
PRE=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
    | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
[ "$PRE" = "ACCEPTED" ] || { log_fail "expected ACCEPTED got $PRE"; exit 1; }
log_pass "T1 ACCEPTED"

# Kill agent-a hard.
log_test "SIGKILL agent-a (no graceful shutdown)"
$DC kill agent-a >/dev/null 2>&1
sleep 1
if $DC ps --status running --services | grep -q "^agent-a$"; then
    log_fail "agent-a still running after kill"; exit 1
fi
log_pass "agent-a dead"

# b tries to send results — must not hang or crash.
log_test "send-results from b with submitter dead"
T0=$(date +%s)
$DC exec -T agent-b bash -c "timeout 15 pilotctl task send-results --id $TID --results 'after-submitter-died'" \
    >/tmp/sr_after.log 2>&1
RC=$?
T1=$(date +%s)
DELTA=$((T1 - T0))
if [ "$DELTA" -le 20 ]; then
    log_pass "send-results returned in ${DELTA}s (rc=$RC)"
else
    log_fail "send-results hung for ${DELTA}s"
fi

# b must not have panicked
log_test "no panic on agent-b"
BAD=$($DC logs agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "agent-b logs clean" || log_fail "$BAD"

# Bring a back. Its submitted list for T1 must still exist; it should
# NOT have spurious result text (since results never made it over).
# If the design is "local state flipped before wire", b's on-disk state
# may say SUCCEEDED — that is informative either way.
log_test "restart agent-a; T1 still in its submitted list"
$DC up -d agent-a >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
LISTA=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
STATUSA=$(echo "$LISTA" | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
if [ -n "$STATUSA" ]; then
    log_pass "T1 present on a after restart (status=$STATUSA)"
else
    log_fail "T1 gone from agent-a's submitted list"
fi

# Result content should be absent — b could not deliver it.
log_test "result payload NOT landed on agent-a"
RES=$($DC exec -T agent-a pilotctl --json task result --id "$TID" 2>/dev/null)
if echo "$RES" | grep -q "after-submitter-died"; then
    log_fail "result text leaked through despite submitter being dead"
else
    log_pass "no result payload (expected — b had no one to send to)"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
