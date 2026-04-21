#!/bin/bash
# Task description payload integrity: submit four tasks whose descriptions
# stress distinct serialization boundaries, and assert that each
# description round-trips byte-exact on BOTH the submitter's and the
# receiver's task listings. A worker then sends generic results so we
# can also assert the description is still intact at result-fetch time.
#
# Adversarial descriptions tested:
#   1. Long: 4 KiB of alternating digits (tests task-record size limits)
#   2. Newline-heavy: "line1\nline2\rline3\n\tindented"
#   3. JSON-in-string: {"nested":"\"json\" with \\ escapes"}
#   4. Unicode: "café 🛰️ ✈ orbit 😀"
#
# Catches:
#   - silent truncation when task is stored as JSON and the struct has
#     a reserved-size field
#   - double-escape / un-escape drift between submit and list endpoints
#   - state-machine transitions that serialize/deserialize the record
#     and mishandle non-ASCII descriptions
#
# All four tasks are submitted in parallel before any completion so the
# polo gate sees a == b == 0 for every submit.

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
echo "Task description payload integrity"
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

# ----- Build adversarial descriptions ---------------------------------
# 4 KiB: 2048 pairs of "01", keeps byte-count predictable.
LONG_DESC=""
for _ in $(seq 1 2048); do LONG_DESC="${LONG_DESC}01"; done
NEWLINE_DESC=$'line1\nline2\rline3\n\tindented\nend'
JSON_DESC='{"nested":"\"json\" with \\ escapes"}'
UNI_DESC="café 🛰️ ✈ orbit 😀"

echo "LONG_DESC    len=${#LONG_DESC}"
echo "NEWLINE_DESC len=${#NEWLINE_DESC}  (bytes: $(printf '%s' "$NEWLINE_DESC" | wc -c))"
echo "JSON_DESC    len=${#JSON_DESC}"
echo "UNI_DESC     len=${#UNI_DESC}  (bytes: $(printf '%s' "$UNI_DESC" | wc -c))"

# ----- 1. Start worker on agent-b that accepts any NEW task -----------
log_test "start accepts-all worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker.log /tmp/worker_stop
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            echo "$(date +%H:%M:%S.%N) accept tid=$TID" >> /tmp/worker.log
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.2
    done
    echo worker-exit >> /tmp/worker.log
'
sleep 1
log_pass "worker running"

# ----- 2. Parallel submit of 4 hostile-description tasks --------------
log_test "agent-a submits 4 tasks in parallel (long, newline, json, unicode)"
R1=$(mktemp); R2=$(mktemp); R3=$(mktemp); R4=$(mktemp)
$DC exec -T agent-a pilotctl --json task submit agent-b --task "$LONG_DESC"    >"$R1" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "$NEWLINE_DESC" >"$R2" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "$JSON_DESC"    >"$R3" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "$UNI_DESC"     >"$R4" 2>&1 &
wait
TID_LONG=$(jq -r '.data.task_id // empty' <"$R1")
TID_NL=$(jq -r   '.data.task_id // empty' <"$R2")
TID_JSON=$(jq -r '.data.task_id // empty' <"$R3")
TID_UNI=$(jq -r  '.data.task_id // empty' <"$R4")
ACC_LONG=$(jq -r '.data.accepted' <"$R1")
ACC_NL=$(jq -r   '.data.accepted' <"$R2")
ACC_JSON=$(jq -r '.data.accepted' <"$R3")
ACC_UNI=$(jq -r  '.data.accepted' <"$R4")
rm -f "$R1" "$R2" "$R3" "$R4"

if [ "$ACC_LONG" = "true" ] && [ "$ACC_NL" = "true" ] && \
   [ "$ACC_JSON" = "true" ] && [ "$ACC_UNI" = "true" ]; then
    log_pass "all 4 submits landed"
else
    log_fail "submits: long=$ACC_LONG nl=$ACC_NL json=$ACC_JSON uni=$ACC_UNI"
    exit 1
fi

# ----- 3. Wait for all 4 to reach COMPLETED ---------------------------
log_test "all 4 tasks reach COMPLETED on submitter within 30s"
status_of() {
    $DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$1" '.data.tasks[]? | select(.task_id == $t) | .status'
}
done_check() { echo "$1" | grep -qiE "completed|succeeded|done"; }
for _ in $(seq 1 30); do
    SL=$(status_of "$TID_LONG")
    SN=$(status_of "$TID_NL")
    SJ=$(status_of "$TID_JSON")
    SU=$(status_of "$TID_UNI")
    if done_check "$SL" && done_check "$SN" && done_check "$SJ" && done_check "$SU"; then break; fi
    sleep 1
done
if done_check "$SL" && done_check "$SN" && done_check "$SJ" && done_check "$SU"; then
    log_pass "long=$SL nl=$SN json=$SJ uni=$SU"
else
    log_fail "non-terminal: long=$SL nl=$SN json=$SJ uni=$SU"
fi

# ----- 4. Submitter-side descriptions round-trip byte-exact -----------
log_test "submitter-side descriptions are byte-exact"
LIST_A=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
desc_of() {
    echo "$LIST_A" | jq -r --arg t "$1" '.data.tasks[]? | select(.task_id == $t) | .description // empty'
}
D_LONG=$(desc_of "$TID_LONG")
D_NL=$(desc_of   "$TID_NL")
D_JSON=$(desc_of "$TID_JSON")
D_UNI=$(desc_of  "$TID_UNI")

FAILS=""
[ "$D_LONG" = "$LONG_DESC" ]    || FAILS="$FAILS long(${#D_LONG}/${#LONG_DESC})"
[ "$D_NL"   = "$NEWLINE_DESC" ] || FAILS="$FAILS newline(${#D_NL}/${#NEWLINE_DESC})"
[ "$D_JSON" = "$JSON_DESC" ]    || FAILS="$FAILS json"
[ "$D_UNI"  = "$UNI_DESC" ]     || FAILS="$FAILS unicode"
if [ -z "$FAILS" ]; then
    log_pass "all 4 descriptions match on submitter side"
else
    log_fail "mismatches:$FAILS"
    [ "$D_LONG" != "$LONG_DESC" ]    && echo "  long: got_len=${#D_LONG} want_len=${#LONG_DESC}"
    [ "$D_NL"   != "$NEWLINE_DESC" ] && echo "  newline: got=$(printf '%s' "$D_NL" | od -c | head -1)"
    [ "$D_JSON" != "$JSON_DESC" ]    && echo "  json got: $D_JSON"
    [ "$D_UNI"  != "$UNI_DESC" ]     && echo "  uni  got: $D_UNI"
fi

# ----- 5. Receiver-side descriptions round-trip byte-exact ------------
log_test "receiver-side descriptions are byte-exact"
LIST_B=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null)
rdesc_of() {
    echo "$LIST_B" | jq -r --arg t "$1" '.data.tasks[]? | select(.task_id == $t) | .description // empty'
}
RD_LONG=$(rdesc_of "$TID_LONG")
RD_NL=$(rdesc_of   "$TID_NL")
RD_JSON=$(rdesc_of "$TID_JSON")
RD_UNI=$(rdesc_of  "$TID_UNI")

FAILS=""
[ "$RD_LONG" = "$LONG_DESC" ]    || FAILS="$FAILS long(${#RD_LONG}/${#LONG_DESC})"
[ "$RD_NL"   = "$NEWLINE_DESC" ] || FAILS="$FAILS newline"
[ "$RD_JSON" = "$JSON_DESC" ]    || FAILS="$FAILS json"
[ "$RD_UNI"  = "$UNI_DESC" ]     || FAILS="$FAILS unicode"
if [ -z "$FAILS" ]; then
    log_pass "all 4 descriptions match on receiver side"
else
    log_fail "mismatches:$FAILS"
fi

# ----- 6. All 4 results correlate (same generic "ok") -----------------
log_test "all 4 tasks have result content 'ok'"
OK=0
for tid in "$TID_LONG" "$TID_NL" "$TID_JSON" "$TID_UNI"; do
    C=$($DC exec -T agent-a pilotctl --json task result "$tid" 2>&1 | jq -r '.data.content // empty')
    if [ "$C" = "ok" ]; then OK=$((OK+1)); fi
done
if [ "$OK" = "4" ]; then
    log_pass "4 results match"
else
    log_fail "$OK/4 results matched"
fi

# ----- 7. No panic/fatal in daemon logs -------------------------------
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
echo "Task description integrity summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
