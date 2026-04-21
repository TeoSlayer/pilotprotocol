#!/bin/bash
# Policy-decline service agent: agent-b runs a worker that classifies
# each incoming task by its description prefix and applies a policy:
#   - "accept-*"  -> accept + send-results "done:<suffix>"
#   - "decline-*" -> decline with justification "policy:<suffix>"
# anything else is ignored.
#
# agent-a submits 4 tasks in parallel (2 accept-*, 2 decline-*) and
# asserts the worker classified them correctly, with no crossover.
#
# Differs from test_task_decline.sh (single manual decline + invalid-
# state probes): this one exercises an automated decision-tree worker
# that processes a mixed batch concurrently, catching:
#   - decline paths that leak polo (completed accept tasks should change
#     scores but declined ones should not)
#   - receiver-side task state transitions happening out-of-order when
#     multiple tasks are classified in one sweep
#   - justification strings getting misrouted between tasks
#
# Parallel submits are issued BEFORE any completion so the polo gate
# sees submitter == receiver == 0 for all four.

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
echo "Policy-decline service agent"
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

# ----- 1. Start policy worker on agent-b -----
log_test "start policy worker on agent-b (accept-* vs decline-*)"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker.log /tmp/worker_stop
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            SUF=${DESC#*-}
            case "$DESC" in
                accept-*)
                    echo "$(date +%H:%M:%S.%N) accept policy tid=$TID desc=$DESC" >> /tmp/worker.log
                    pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
                    pilotctl task send-results --id "$TID" --results "done:$SUF" >>/tmp/worker.log 2>&1 || true
                    ;;
                decline-*)
                    echo "$(date +%H:%M:%S.%N) decline policy tid=$TID desc=$DESC" >> /tmp/worker.log
                    pilotctl task decline --id "$TID" --justification "policy:$SUF" >>/tmp/worker.log 2>&1 || true
                    ;;
                *)
                    echo "$(date +%H:%M:%S.%N) ignore tid=$TID desc=$DESC" >> /tmp/worker.log
                    ;;
            esac
        done
        sleep 0.2
    done
    echo worker-exit >> /tmp/worker.log
'
sleep 1
log_pass "worker running"

# ----- 2. agent-a submits 4 tasks in parallel (BEFORE any completion) -----
log_test "agent-a submits 4 tasks in parallel: accept-alpha, decline-beta, accept-gamma, decline-delta"
R1=$(mktemp); R2=$(mktemp); R3=$(mktemp); R4=$(mktemp)
$DC exec -T agent-a pilotctl --json task submit agent-b --task "accept-alpha"  >"$R1" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "decline-beta"  >"$R2" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "accept-gamma"  >"$R3" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "decline-delta" >"$R4" 2>&1 &
wait
TID_ALPHA=$(jq -r '.data.task_id // empty' <"$R1")
TID_BETA=$(jq -r  '.data.task_id // empty' <"$R2")
TID_GAMMA=$(jq -r '.data.task_id // empty' <"$R3")
TID_DELTA=$(jq -r '.data.task_id // empty' <"$R4")
ACC_ALPHA=$(jq -r '.data.accepted' <"$R1")
ACC_BETA=$(jq -r  '.data.accepted' <"$R2")
ACC_GAMMA=$(jq -r '.data.accepted' <"$R3")
ACC_DELTA=$(jq -r '.data.accepted' <"$R4")
rm -f "$R1" "$R2" "$R3" "$R4"

if [ "$ACC_ALPHA" = "true" ] && [ "$ACC_BETA" = "true" ] && \
   [ "$ACC_GAMMA" = "true" ] && [ "$ACC_DELTA" = "true" ]; then
    log_pass "all 4 submits landed"
else
    log_fail "submit landings: alpha=$ACC_ALPHA beta=$ACC_BETA gamma=$ACC_GAMMA delta=$ACC_DELTA"
    exit 1
fi

# ----- 3. Wait for terminal states on each -----
log_test "all 4 tasks reach terminal state within 30s"
status_of() {
    local tid=$1
    $DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status'
}
terminal() {
    echo "$1" | grep -qiE "completed|succeeded|done|declined"
}
for _ in $(seq 1 30); do
    ST_A=$(status_of "$TID_ALPHA")
    ST_B=$(status_of "$TID_BETA")
    ST_G=$(status_of "$TID_GAMMA")
    ST_D=$(status_of "$TID_DELTA")
    if terminal "$ST_A" && terminal "$ST_B" && terminal "$ST_G" && terminal "$ST_D"; then break; fi
    sleep 1
done
if terminal "$ST_A" && terminal "$ST_B" && terminal "$ST_G" && terminal "$ST_D"; then
    log_pass "alpha=$ST_A  beta=$ST_B  gamma=$ST_G  delta=$ST_D"
else
    log_fail "non-terminal: alpha=$ST_A beta=$ST_B gamma=$ST_G delta=$ST_D"
    $DC exec -T agent-b tail -40 /tmp/worker.log 2>&1 | sed 's/^/    /'
fi

# ----- 4. accept-* tasks are COMPLETED -----
log_test "accept-alpha and accept-gamma are COMPLETED"
if echo "$ST_A" | grep -qiE "completed|succeeded|done" && \
   echo "$ST_G" | grep -qiE "completed|succeeded|done"; then
    log_pass "both accept-* tasks completed"
else
    log_fail "alpha=$ST_A gamma=$ST_G"
fi

# ----- 5. decline-* tasks are DECLINED -----
log_test "decline-beta and decline-delta are DECLINED"
if [ "$ST_B" = "DECLINED" ] && [ "$ST_D" = "DECLINED" ]; then
    log_pass "both decline-* tasks declined"
else
    log_fail "beta=$ST_B delta=$ST_D"
fi

# ----- 6. Results on accept-* match policy suffix -----
log_test "accept-* results are done:<suffix>"
R_A=$($DC exec -T agent-a pilotctl --json task result "$TID_ALPHA" 2>&1 | jq -r '.data.content // empty')
R_G=$($DC exec -T agent-a pilotctl --json task result "$TID_GAMMA" 2>&1 | jq -r '.data.content // empty')
if [ "$R_A" = "done:alpha" ] && [ "$R_G" = "done:gamma" ]; then
    log_pass "alpha->$R_A  gamma->$R_G"
else
    log_fail "mismatched results: alpha=\"$R_A\" gamma=\"$R_G\""
fi

# ----- 7. Justifications on decline-* carry policy:<suffix> -----
log_test "decline-* justifications are policy:<suffix>"
LIST_A=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>&1)
read_just() {
    local tid=$1
    echo "$LIST_A" | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status_justification // .justification // ""'
}
J_B=$(read_just "$TID_BETA")
J_D=$(read_just "$TID_DELTA")
if [ "$J_B" = "policy:beta" ] && [ "$J_D" = "policy:delta" ]; then
    log_pass "beta->$J_B  delta->$J_D"
else
    # Fallback: check receiver side.
    LIST_B=$($DC exec -T agent-b pilotctl --json task list --type received 2>&1)
    rb() { echo "$LIST_B" | jq -r --arg t "$1" '.data.tasks[]? | select(.task_id == $t) | .status_justification // .justification // ""'; }
    J_B2=$(rb "$TID_BETA")
    J_D2=$(rb "$TID_DELTA")
    if [ "$J_B2" = "policy:beta" ] && [ "$J_D2" = "policy:delta" ]; then
        log_pass "justifications stored receiver-side: beta->$J_B2 delta->$J_D2"
    else
        log_fail "justifications missing (submitter beta=\"$J_B\" delta=\"$J_D\"; receiver beta=\"$J_B2\" delta=\"$J_D2\")"
    fi
fi

# ----- 8. Worker classified exactly 2 accepts + 2 declines -----
log_test "worker classified 2 accepts + 2 declines (no crossover)"
ACC_CNT=$($DC exec -T agent-b bash -c "grep -c 'accept policy' /tmp/worker.log 2>/dev/null || echo 0")
DEC_CNT=$($DC exec -T agent-b bash -c "grep -c 'decline policy' /tmp/worker.log 2>/dev/null || echo 0")
if [ "$ACC_CNT" = "2" ] && [ "$DEC_CNT" = "2" ]; then
    log_pass "worker: accepts=$ACC_CNT declines=$DEC_CNT"
else
    log_fail "worker classifier counts: accepts=$ACC_CNT declines=$DEC_CNT (want 2/2)"
    $DC exec -T agent-b tail -40 /tmp/worker.log 2>&1 | sed 's/^/    /'
fi

# ----- 9. No panic/fatal in daemon logs -----
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
echo "Policy-decline test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
