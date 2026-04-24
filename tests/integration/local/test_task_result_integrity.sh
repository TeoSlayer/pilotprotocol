#!/bin/bash
# Task result content integrity: the worker returns hostile payloads
# via send-results and we assert each result round-trips byte-exact
# on the submitter side via `pilotctl task result`.
#
# Parallel to test_task_description_integrity.sh (which stresses the
# .description field) but for the result/content field. This is a
# different code path — results are returned via a separate message
# back to the submitter, then stored under
#   ~/.pilot/tasks/submitted/<tid>.json on the submitter side.
#
# Worker routes by description prefix:
#   result:long    -> 8 KiB of 'x'
#   result:newline -> "alpha\nbeta\rgamma\n\tdelta\nend"
#   result:json    -> {"nested":"\"json\" with \\ escapes"}
#   result:uni     -> "café 🛰️ ✈ orbit 😀"
#
# Catches bugs where:
#   - send-results truncates / silently shortens large payloads
#   - JSON encoding of the result mangles escapes on a second-hop
#     (submit frame -> stored record -> task-result command)
#   - UTF-8 bytes are treated as ASCII when stored in the task record
#
# All four submits are issued in parallel BEFORE any completion so the
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
echo "Task result content integrity"
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

# ----- Expected result payloads (built on the HOST so we can compare) ----
LONG_RES=$(printf 'x%.0s' $(seq 1 8192))
NEWLINE_RES=$'alpha\nbeta\rgamma\n\tdelta\nend'
JSON_RES='{"nested":"\"json\" with \\ escapes"}'
UNI_RES="café 🛰️ ✈ orbit 😀"

echo "LONG_RES    len=${#LONG_RES}"
echo "NEWLINE_RES len=${#NEWLINE_RES}"
echo "JSON_RES    len=${#JSON_RES}"
echo "UNI_RES     len=${#UNI_RES}  (bytes: $(printf '%s' "$UNI_RES" | wc -c))"

# ----- 1. Worker on agent-b that routes by description ---------------
# Uses HEREDOC with escaping for inner bash. Builds the SAME payloads
# inside the container so no bash-to-bash escape surprises.
log_test "start description-routing worker on agent-b"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker.log /tmp/worker_stop
    build_long() { local n=""; local i; for i in $(seq 1 8192); do n="${n}x"; done; printf "%s" "$n"; }
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            echo "$(date +%H:%M:%S.%N) accept tid=$TID desc=$DESC" >> /tmp/worker.log
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            case "$DESC" in
                result:long)
                    PAYLOAD=$(build_long)
                    ;;
                result:newline)
                    PAYLOAD=$(printf "alpha\nbeta\rgamma\n\tdelta\nend")
                    ;;
                result:json)
                    PAYLOAD="{\"nested\":\"\\\"json\\\" with \\\\ escapes\"}"
                    ;;
                result:uni)
                    PAYLOAD="café 🛰️ ✈ orbit 😀"
                    ;;
                *)
                    PAYLOAD="unknown"
                    ;;
            esac
            pilotctl task send-results --id "$TID" --results "$PAYLOAD" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.2
    done
    echo worker-exit >> /tmp/worker.log
'
sleep 1
log_pass "worker running"

# ----- 2. Parallel submit of 4 description-routed tasks --------------
log_test "agent-a submits 4 tasks in parallel (long/newline/json/uni)"
R1=$(mktemp); R2=$(mktemp); R3=$(mktemp); R4=$(mktemp)
$DC exec -T agent-a pilotctl --json task submit agent-b --task "result:long"    >"$R1" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "result:newline" >"$R2" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "result:json"    >"$R3" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "result:uni"     >"$R4" 2>&1 &
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

# ----- 3. Wait for all 4 COMPLETED on submitter ----------------------
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
    $DC exec -T agent-b tail -30 /tmp/worker.log 2>&1 | sed 's/^/    /'
    exit 1
fi

# ----- 4. Long result (8 KiB) byte-exact -----------------------------
log_test "long result (8 KiB) byte-exact round-trip"
GOT=$($DC exec -T agent-a pilotctl --json task result "$TID_LONG" 2>&1 | jq -r '.data.content // empty')
if [ "$GOT" = "$LONG_RES" ]; then
    log_pass "long result matches (len=${#LONG_RES})"
else
    log_fail "long mismatch got_len=${#GOT} want_len=${#LONG_RES}"
    echo "    first 80 got:  $(printf '%s' "$GOT" | head -c 80)"
fi

# ----- 5. Newline-heavy result byte-exact ----------------------------
log_test "newline-heavy result byte-exact round-trip"
GOT=$($DC exec -T agent-a pilotctl --json task result "$TID_NL" 2>&1 | jq -r '.data.content // empty')
if [ "$GOT" = "$NEWLINE_RES" ]; then
    log_pass "newline result matches"
else
    log_fail "newline mismatch"
    echo "    got  bytes: $(printf '%s' "$GOT"         | od -c | head -2)"
    echo "    want bytes: $(printf '%s' "$NEWLINE_RES" | od -c | head -2)"
fi

# ----- 6. JSON-escape result byte-exact ------------------------------
log_test "JSON-escape-heavy result byte-exact round-trip"
GOT=$($DC exec -T agent-a pilotctl --json task result "$TID_JSON" 2>&1 | jq -r '.data.content // empty')
if [ "$GOT" = "$JSON_RES" ]; then
    log_pass "json result matches"
else
    log_fail "json mismatch"
    echo "    got:  $GOT"
    echo "    want: $JSON_RES"
fi

# ----- 7. UTF-8 unicode result byte-exact ----------------------------
log_test "UTF-8 unicode result byte-exact round-trip"
GOT=$($DC exec -T agent-a pilotctl --json task result "$TID_UNI" 2>&1 | jq -r '.data.content // empty')
if [ "$GOT" = "$UNI_RES" ]; then
    log_pass "unicode result matches: $GOT"
else
    log_fail "unicode mismatch"
    echo "    got:  $GOT"
    echo "    want: $UNI_RES"
fi

# ----- 8. No panic/fatal in daemon logs ------------------------------
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
echo "Task result integrity summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
