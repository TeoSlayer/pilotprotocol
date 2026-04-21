#!/bin/bash
# Task-executor with file-based results: agent-b answers tasks by returning
# a generated file (csv, md, pdf-ish) via `pilotctl task send-results --file`.
# agent-a retrieves each result with `pilotctl task result --out <path>` and
# verifies bytes round-tripped intact.
#
# Also checks the client-side extension gate rejects forbidden source code
# extensions (.go) and unsupported extensions (.sh).

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

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Task file-results integration"
echo "=========================================="

log_test "Starting p2p stack (clean)"
docker compose -f docker-compose.multi.yml down -v >/dev/null 2>&1
docker compose -f docker-compose.multi.yml up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "both agents registered"
else
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

# ----- 1. Enable tasks on both sides (for balanced polo flow) -----
log_test "enable-tasks on both agents"
docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
log_pass "enable-tasks ok"

# Helper: wait until a task reaches a terminal success state on the submitter.
wait_for_done() {
    local agent=$1 tid=$2
    for _ in $(seq 1 30); do
        local st
        st=$(docker compose -f docker-compose.multi.yml exec -T "$agent" \
             pilotctl --json task list --type submitted 2>/dev/null \
             | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$st" | grep -qiE "completed|succeeded|done"; then
            echo "$st"
            return 0
        fi
        sleep 1
    done
    echo "$st"
    return 1
}

# ----- 2. Before the auto-worker starts, exercise the extension gate -----
# Submit a task that stays in ACCEPTED state (no worker to complete it) so
# we can try forbidden and unsupported extensions on it.
log_test "agent-a submits T0 for extension-gate checks"
SUBMIT0=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "gate-check" 2>&1)
TID0=$(echo "$SUBMIT0" | jq -r '.data.task_id // empty')
if [ -n "$TID0" ]; then
    log_pass "T0 submitted: $TID0"
else
    log_fail "T0 submit rejected: $(echo "$SUBMIT0" | head -c 200)"
    exit 1
fi

log_test "agent-b accepts T0 (manual, so task stays in ACCEPTED)"
ACCEPT0=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task accept --id "$TID0" 2>&1)
if echo "$ACCEPT0" | jq -e '.data.status == "ACCEPTED"' >/dev/null 2>&1; then
    log_pass "T0 accepted"
else
    log_fail "T0 accept failed: $(echo "$ACCEPT0" | head -c 200)"
fi

log_test "send-results rejects forbidden .go extension"
docker compose -f docker-compose.multi.yml exec -T agent-b bash -c 'echo "package main" > /tmp/source.go'
REJECT_GO=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task send-results --id "$TID0" --file /tmp/source.go 2>&1)
if echo "$REJECT_GO" | grep -qE "not allowed|source code files cannot be sent|forbidden"; then
    log_pass ".go rejected"
else
    log_fail ".go not rejected: $(echo "$REJECT_GO" | head -c 200)"
fi

log_test "send-results rejects unsupported .sh extension"
docker compose -f docker-compose.multi.yml exec -T agent-b bash -c 'echo "#!/bin/bash" > /tmp/script.sh'
REJECT_SH=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task send-results --id "$TID0" --file /tmp/script.sh 2>&1)
if echo "$REJECT_SH" | grep -qE "not allowed|invalid_argument"; then
    log_pass ".sh rejected"
else
    log_fail ".sh not rejected: $(echo "$REJECT_SH" | head -c 200)"
fi

# Complete T0 properly so polo bookkeeping is clean before the csv test.
log_test "complete T0 with a valid .csv file"
docker compose -f docker-compose.multi.yml exec -T agent-b bash -c 'printf "a,b\n1,2\n" > /tmp/t0.csv'
docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl task send-results --id "$TID0" --file /tmp/t0.csv >/dev/null 2>&1
T0_DONE=$(wait_for_done agent-a "$TID0")
if echo "$T0_DONE" | grep -qiE "completed|succeeded|done"; then
    log_pass "T0 completed after gate checks (status=$T0_DONE)"
else
    log_fail "T0 stuck at $T0_DONE"
fi

# ----- 3. Rebalance polo: enable tasks on agent-a and run b -> a reverse flow -----
log_test "rebalance polo via reverse b -> a round-trip"
docker compose -f docker-compose.multi.yml exec -d agent-a bash -c '
rm -f /tmp/worker_stop
while [ ! -f /tmp/worker_stop ]; do
    LIST=$(pilotctl --json task list --type received 2>/dev/null)
    for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
        DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
        pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
        mkdir -p /tmp/results
        OUT="/tmp/results/${TID}.md"
        printf "# Result for %s\n- desc: %s\n" "$TID" "$DESC" > "$OUT"
        pilotctl task send-results --id "$TID" --file "$OUT" >>/tmp/worker.log 2>&1 || true
    done
    sleep 0.3
done
'
SUBMIT_R=$(docker compose -f docker-compose.multi.yml exec -T agent-b pilotctl --json task submit agent-a --task "rebalance" 2>&1)
RTID=$(echo "$SUBMIT_R" | jq -r '.data.task_id // empty')
if [ -n "$RTID" ]; then
    wait_for_done agent-b "$RTID" >/dev/null
    log_pass "reverse flow complete (rtid=$RTID)"
else
    log_fail "reverse submit failed: $(echo "$SUBMIT_R" | head -c 200)"
fi

# ----- 4. Start auto-worker on agent-b that returns .csv; full round-trip -----
log_test "start file-returning worker on agent-b"
docker compose -f docker-compose.multi.yml exec -d agent-b bash -c '
rm -f /tmp/worker_stop
while [ ! -f /tmp/worker_stop ]; do
    LIST=$(pilotctl --json task list --type received 2>/dev/null)
    for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
        DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
        pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
        mkdir -p /tmp/results
        OUT="/tmp/results/${TID}.csv"
        {
            echo "task_id,description,row"
            echo "${TID},${DESC},1"
            echo "${TID},${DESC},2"
            echo "${TID},${DESC},3"
        } > "$OUT"
        pilotctl task send-results --id "$TID" --file "$OUT" >>/tmp/worker.log 2>&1 || true
    done
    sleep 0.3
done
echo worker-exit >> /tmp/worker.log
'
sleep 1
log_pass "worker started on agent-b"

log_test "agent-a submits T1 for .csv result"
SUBMIT=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task submit agent-b --task "export-rows" 2>&1)
TID1=$(echo "$SUBMIT" | jq -r '.data.task_id // empty')
if [ -n "$TID1" ] && [ "$(echo "$SUBMIT" | jq -r '.data.accepted')" = "true" ]; then
    log_pass "T1 submitted: $TID1"
else
    log_fail "T1 submit rejected: $(echo "$SUBMIT" | head -c 300)"
    exit 1
fi

log_test "T1 completes on submitter"
T1_STATUS=$(wait_for_done agent-a "$TID1")
if echo "$T1_STATUS" | grep -qiE "completed|succeeded|done"; then
    log_pass "T1 status=$T1_STATUS"
else
    log_fail "T1 stuck at status=$T1_STATUS"
fi

log_test "pilotctl task result reports file type and size"
META=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task result "$TID1" 2>&1)
TYPE=$(echo "$META" | jq -r '.data.type // empty')
FNAME=$(echo "$META" | jq -r '.data.filename // empty')
SIZE=$(echo "$META" | jq -r '.data.size // 0')
if [ "$TYPE" = "file" ] && [ "$FNAME" = "${TID1}.csv" ] && [ "$SIZE" -gt 0 ]; then
    log_pass "metadata ok (type=$TYPE filename=$FNAME size=$SIZE)"
else
    log_fail "unexpected metadata: $(echo "$META" | head -c 300)"
fi

log_test "--out writes the csv locally with matching content"
docker compose -f docker-compose.multi.yml exec -T agent-a rm -f /tmp/pulled.csv
WRITTEN=$(docker compose -f docker-compose.multi.yml exec -T agent-a pilotctl --json task result "$TID1" --out /tmp/pulled.csv 2>&1)
WROTE_TO=$(echo "$WRITTEN" | jq -r '.data.written // empty')
PULLED_HEAD=$(docker compose -f docker-compose.multi.yml exec -T agent-a head -1 /tmp/pulled.csv 2>/dev/null)
PULLED_ROW=$(docker compose -f docker-compose.multi.yml exec -T agent-a grep -c "export-rows" /tmp/pulled.csv 2>/dev/null)
if [ "$WROTE_TO" = "/tmp/pulled.csv" ] && [ "$PULLED_HEAD" = "task_id,description,row" ] && [ "$PULLED_ROW" = "3" ]; then
    log_pass "csv round-trip ok (3 rows, header intact)"
else
    log_fail "csv content wrong (written=$WROTE_TO head=\"$PULLED_HEAD\" rows=$PULLED_ROW)"
fi

# ----- 5. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$(docker compose -f docker-compose.multi.yml logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found panic/fatal entries: $BAD"
fi

# Cleanup workers
docker compose -f docker-compose.multi.yml exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
docker compose -f docker-compose.multi.yml exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "File-results test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
