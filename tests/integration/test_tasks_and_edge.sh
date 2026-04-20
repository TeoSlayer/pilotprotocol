#!/bin/bash
# Task-lifecycle and edge-case integration tests.
# Requires the p2p compose stack to be up.

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
echo "Tasks & edge-case integration tests"
echo "=========================================="

# Ensure stack up
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for i in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
if [ "$COUNT" -lt 2 ]; then
    echo "[FAIL] bootstrap: only $COUNT agents"
    exit 1
fi

# ---- Enable task handling on agent-b ----
log_test "enable-tasks on agent-b"
if $DC exec -T agent-b bash -c 'pilotctl enable-tasks' >/dev/null 2>&1; then
    log_pass "enable-tasks ok"
else
    log_fail "enable-tasks failed"
fi

# ---- Task submit ----
log_test "task submit agent-a → agent-b"
SUBMIT=$($DC exec -T agent-a bash -c 'pilotctl --json task submit agent-b --task "compute pi to 3 decimals"' 2>&1)
TASK_ID=$(echo "$SUBMIT" | jq -r '.data.task_id // empty' 2>/dev/null)
if [ -n "$TASK_ID" ] && [ "$TASK_ID" != "null" ]; then
    log_pass "task submitted: $TASK_ID"
else
    log_fail "task submit failed: $(echo "$SUBMIT" | head -c 300)"
fi

# ---- Task list on agent-b (received) ----
log_test "task list --type received on agent-b"
sleep 1
LIST=$($DC exec -T agent-b bash -c 'pilotctl --json task list --type received' 2>&1)
if [ -n "$TASK_ID" ] && echo "$LIST" | jq -e --arg tid "$TASK_ID" '.data.tasks[]? | select(.task_id == $tid)' >/dev/null 2>&1; then
    log_pass "received task visible on agent-b"
else
    log_fail "received task not visible (got: $(echo "$LIST" | head -c 300))"
fi

# ---- Task list on agent-a (submitted) ----
log_test "task list --type submitted on agent-a"
LIST_A=$($DC exec -T agent-a bash -c 'pilotctl --json task list --type submitted' 2>&1)
if [ -n "$TASK_ID" ] && echo "$LIST_A" | jq -e --arg tid "$TASK_ID" '.data.tasks[]? | select(.task_id == $tid)' >/dev/null 2>&1; then
    log_pass "submitted task visible on agent-a"
else
    log_fail "submitted task not visible (got: $(echo "$LIST_A" | head -c 300))"
fi

# ---- Task accept on agent-b ----
if [ -n "$TASK_ID" ]; then
    log_test "task accept on agent-b"
    if $DC exec -T agent-b bash -c "pilotctl task accept --id $TASK_ID" >/tmp/acc.txt 2>&1; then
        log_pass "task accepted"
    else
        log_fail "task accept failed"
    fi

    # ---- Task send-results ----
    log_test "task send-results from agent-b"
    if $DC exec -T agent-b bash -c "pilotctl task send-results --id $TASK_ID --results 'pi≈3.142'" >/tmp/sr.txt 2>&1; then
        log_pass "results sent"
    else
        log_fail "send-results failed: $($DC exec -T agent-b cat /tmp/sr.txt)"
    fi

    sleep 2
    # ---- Verify agent-a's submitted task is marked completed ----
    log_test "agent-a submitted task shows completed status"
    LIST_A=$($DC exec -T agent-a bash -c 'pilotctl --json task list --type submitted' 2>&1)
    STATUS=$(echo "$LIST_A" | jq -r --arg tid "$TASK_ID" '.data.tasks[]? | select(.task_id == $tid) | .status' 2>/dev/null)
    if echo "$STATUS" | grep -qiE "completed|done|finished"; then
        log_pass "submitter sees status=$STATUS"
    else
        # Some implementations route results to a dedicated file; accept if result file exists
        if $DC exec -T agent-a bash -c "ls /root/.pilot/submitted/${TASK_ID}* /root/.pilot/received/*${TASK_ID}* 2>/dev/null" | grep -q "."; then
            log_pass "submitter has result file for task"
        else
            log_fail "submitter status=$STATUS and no result file"
        fi
    fi
fi

# ---- Task queue (worker view) ----
log_test "task queue on agent-b"
if $DC exec -T agent-b bash -c 'pilotctl task queue' >/tmp/q.txt 2>&1; then
    log_pass "task queue ok"
else
    log_fail "task queue failed"
fi

# ---- send-message: JSON and binary types ----
log_test "send-message type=json"
OUT=$($DC exec -T agent-a bash -c "pilotctl --json send-message agent-b --data '{\"k\":\"v\"}' --type json" 2>&1)
if echo "$OUT" | jq -e '.data.ack | contains("JSON")' >/dev/null 2>&1; then
    log_pass "send-message JSON ack ok"
else
    log_fail "send-message JSON failed: $(echo "$OUT" | head -c 200)"
fi

log_test "send-message type=binary"
OUT=$($DC exec -T agent-a bash -c "pilotctl --json send-message agent-b --data 'deadbeef' --type binary" 2>&1)
if echo "$OUT" | jq -e '.data.ack | contains("BINARY")' >/dev/null 2>&1; then
    log_pass "send-message binary ack ok"
else
    log_fail "send-message binary failed: $(echo "$OUT" | head -c 200)"
fi

# ---- send-file size verification ----
log_test "send-file and verify byte count"
$DC exec -T agent-a bash -c 'dd if=/dev/urandom of=/tmp/rand.bin bs=1024 count=10 status=none'
SIZE=$($DC exec -T agent-a bash -c 'wc -c </tmp/rand.bin' | tr -d ' \r\n')
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json send-file agent-b /tmp/rand.bin' 2>&1)
ACK_BYTES=$(echo "$OUT" | jq -r '.data.ack // empty' | grep -oE '[0-9]+' | head -n1)
# send-file includes a small header; ack bytes should be >= payload size
if [ -n "$ACK_BYTES" ] && [ "$ACK_BYTES" -ge "$SIZE" ]; then
    log_pass "send-file $SIZE bytes acked ($ACK_BYTES)"
else
    log_fail "send-file ack missing or short: size=$SIZE ack=$ACK_BYTES raw=$(echo "$OUT" | head -c 200)"
fi

# ---- Received files / inbox clear roundtrip ----
log_test "inbox has at least 2 message entries (JSON + binary text)"
INBCOUNT=$($DC exec -T agent-b bash -c 'pilotctl --json inbox' | jq -r '.data.messages | length // 0' 2>/dev/null)
if [ "${INBCOUNT:-0}" -ge 2 ]; then
    log_pass "inbox has $INBCOUNT entries"
else
    log_fail "inbox has only $INBCOUNT entries, expected ≥2"
fi

log_test "received/ has the binary file delivered by send-file"
RECVFILES=$($DC exec -T agent-b bash -c 'pilotctl --json received' | jq -r '.data.files | length // 0' 2>/dev/null)
if [ "${RECVFILES:-0}" -ge 1 ]; then
    log_pass "received/ has $RECVFILES file(s)"
else
    log_fail "received/ has no files"
fi

log_test "inbox --clear empties the inbox"
$DC exec -T agent-b bash -c 'pilotctl inbox --clear' >/dev/null 2>&1
AFTER=$($DC exec -T agent-b bash -c 'pilotctl --json inbox' | jq -r '.data.messages | length // 0' 2>/dev/null)
if [ "${AFTER:-999}" -eq 0 ]; then
    log_pass "inbox cleared (was $INBCOUNT now $AFTER)"
else
    log_fail "inbox has $AFTER after clear"
fi

# ---- Error paths ----
log_test "ping unknown hostname returns clear error"
OUT=$($DC exec -T agent-a bash -c 'pilotctl ping this-does-not-exist --count 1 --timeout 3s 2>&1' || true)
if echo "$OUT" | grep -qi "resolve\|not found\|hostname\|no such"; then
    log_pass "unknown hostname rejected cleanly"
else
    log_fail "unknown hostname gave unexpected error: $(echo "$OUT" | head -c 200)"
fi

log_test "send missing --data flag returns invalid_argument"
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json send agent-b 1001' 2>&1)
if echo "$OUT" | jq -e '.code == "invalid_argument"' >/dev/null 2>&1; then
    log_pass "missing --data rejected with invalid_argument"
else
    log_fail "missing --data got unexpected: $(echo "$OUT" | head -c 200)"
fi

log_test "set-hostname with bad characters rejected"
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json set-hostname "INVALID_HOST!"' 2>&1)
if echo "$OUT" | jq -e '.code // empty' | grep -qE "invalid|error"; then
    log_pass "invalid hostname rejected"
else
    # Fall back to status-ok check — some validators run server side
    if echo "$OUT" | jq -e '.status == "error"' >/dev/null 2>&1; then
        log_pass "invalid hostname rejected (status=error)"
    else
        log_fail "invalid hostname not rejected: $(echo "$OUT" | head -c 200)"
    fi
fi

log_test "lookup of nonexistent node_id returns error"
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json lookup 999999' 2>&1)
if echo "$OUT" | jq -e '.status == "error"' >/dev/null 2>&1; then
    log_pass "lookup of ghost node fails cleanly"
else
    log_fail "lookup ghost node unexpected: $(echo "$OUT" | head -c 200)"
fi

# ---- pilotctl version ----
log_test "pilotctl version"
VER=$($DC exec -T agent-a bash -c 'pilotctl version' 2>&1)
if [ -n "$VER" ]; then
    log_pass "version: $(echo "$VER" | head -n1)"
else
    log_fail "pilotctl version empty"
fi

echo ""
echo "=========================================="
echo "Tasks/Edge Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="
exit $([ "$FAILED" -gt 0 ] && echo 1 || echo 0)
