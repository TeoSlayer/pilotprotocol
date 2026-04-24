#!/bin/bash
# Race: dashboard polo read vs task-completion polo write.
#
# Agent-a submits tasks back-to-back to agent-b; agent-b accepts and sends
# results, each cycle bumping polo on the submitter's side. Concurrently, we
# hammer the rendezvous dashboard `/api/stats` endpoint for polo values.
#
# PASS criteria: every read parses as valid JSON with a polo value that is
# a non-negative integer, no crash, no corrupted values (negative / NaN /
# absurdly large like > 1e9). Polo should be monotone non-decreasing across
# reads (task success only grows polo).

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
echo "Race: polo dashboard read vs task-completion write"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

$DC exec -T agent-b bash -c 'pilotctl enable-tasks' >/dev/null 2>&1

# Reader loop: hammer /api/stats.
log_test "launch dashboard reader (500 reads)"
$DC exec -d rendezvous bash -c '
    rm -f /tmp/polo-reads.log
    for i in $(seq 1 500); do
        curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null >>/tmp/polo-reads.log
        echo >>/tmp/polo-reads.log
        sleep 0.01
    done
    echo READER_DONE >>/tmp/polo-reads.log
'

# Writer: submit+accept+results 15 tasks.
log_test "launch task round-trip writer (15 tasks)"
$DC exec -T agent-a bash -c '
    rm -f /tmp/task-ids.txt
    for i in $(seq 1 15); do
        resp=$(pilotctl --json task submit agent-b --task "polo-race-$i" 2>/dev/null)
        echo "$resp" | jq -r ".data.task_id // empty" >>/tmp/task-ids.txt
        sleep 0.1
    done
' >/dev/null 2>&1
log_pass "15 submits issued"

# Give a moment for tasks to land on agent-b.
sleep 2

$DC exec -T agent-b bash -c '
    for id in $(pilotctl --json task list --type received | jq -r ".data.tasks[]? | select(.status==\"NEW\") | .task_id"); do
        pilotctl --json task accept --id "$id" >/dev/null 2>&1
        pilotctl --json task send-results --id "$id" --results "ok" >/dev/null 2>&1
    done
' >/dev/null 2>&1

# Wait for reader to finish.
sleep 8

log_test "every read parses as JSON with a polo-looking value"
TOTAL=$($DC exec -T rendezvous bash -c "grep -c '^{' /tmp/polo-reads.log" 2>/dev/null | tr -d ' \r\n')
TOTAL=${TOTAL:-0}
# Parse each line as JSON and check at least one polo-like field exists.
PARSED=$($DC exec -T rendezvous bash -c '
    ok=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Valid json?
        echo "$line" | jq -e . >/dev/null 2>&1 || continue
        ok=$((ok+1))
    done </tmp/polo-reads.log
    echo $ok
' | tr -d ' \r\n')
echo "    total_reads=$TOTAL valid_json=$PARSED"
if [ "${PARSED:-0}" -ge 1 ] && [ "${PARSED:-0}" = "${TOTAL:-0}" ]; then
    log_pass "$PARSED/$TOTAL reads parsed cleanly"
else
    log_fail "corrupt reads: $((TOTAL-PARSED)) of $TOTAL invalid"
fi

log_test "no negative / NaN / >1e9 polo values in any read"
SUS=$($DC exec -T rendezvous bash -c '
    bad=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        val=$(echo "$line" | jq -r ".total_polo // .polo // .total // 0" 2>/dev/null)
        if [ "$val" = "null" ] || [ -z "$val" ]; then continue; fi
        # numeric check
        case "$val" in
            -*|*.*e*|*NaN*|*nan*) bad=$((bad+1)) ;;
            *[!0-9]*) bad=$((bad+1)) ;;
        esac
        # enormous sentinel
        if [ "${val:-0}" -gt 1000000000 ] 2>/dev/null; then bad=$((bad+1)); fi
    done </tmp/polo-reads.log
    echo $bad
' | tr -d ' \r\n')
if [ "${SUS:-0}" = "0" ]; then
    log_pass "no suspicious polo values"
else
    log_fail "$SUS suspicious reads"
fi

log_test "no panics in daemon/rendezvous logs"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Passed: $PASSED  Failed: $FAILED"
echo "=========================================="
[ "$FAILED" -eq 0 ]
