#!/bin/bash
# Task-message service chain: agent-b's task worker needs help from agent-a
# to complete its work. Shape:
#   1. agent-a submits task "compute:<N>" to agent-b.
#   2. agent-b's task-worker accepts the task, but to finish it needs a
#      "multiplier" from agent-a. It sends a JSON message {req,op:"mul"}
#      to agent-a and waits for a text reply "mul:<req>:<value>".
#   3. agent-a runs a SEPARATE message-responder worker that watches its
#      inbox for JSON mul requests and replies back.
#   4. agent-b's task-worker reads the reply from its own inbox, extracts
#      the multiplier, computes N*mul, and sends task results.
#   5. agent-a asserts the tasks COMPLETED with the right content.
#
# This is a cross-subsystem service-agent pattern that exercises BOTH the
# tasksubmit service AND the dataexchange (inbox) service at the same time
# on the same pair of daemons. It catches bugs where:
#   - task receiver-side file updates race with regular inbox message writes
#   - the send-message path is blocked while a task is ACCEPTED on the
#     same daemon (unexpected serialization between subsystems)
#   - reply correlation fails when several tasks run concurrently
#   - inbox read-then-delete by one worker consumes files the other needs
#
# We run TWO tasks (N=3 and N=5) concurrently so the correlation by `req`
# id has to hold up under interleaving.

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
MULTIPLIER=7

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Task-message service chain integration"
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
    log_fail "agents did not register (total_nodes=$COUNT)"
    exit 1
fi

$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

$DC exec -T agent-a pilotctl --json inbox --clear >/dev/null 2>&1
$DC exec -T agent-b pilotctl --json inbox --clear >/dev/null 2>&1

# ----- 1. Start the JSON message-responder on agent-a -----
# Reads JSON messages from inbox, parses {req,op}, replies with
# "mul:<req>:<MULTIPLIER>" to the sender. Only consumes JSON messages
# whose op is "mul"; leaves anything else alone.
log_test "start message-responder on agent-a (inbox JSON watcher)"
$DC exec -d agent-a bash -c "
    rm -f /tmp/responder.log /tmp/responder_stop
    INBOX=/root/.pilot/inbox
    while [ ! -f /tmp/responder_stop ]; do
        for f in \$(ls -1 \$INBOX/*.json 2>/dev/null); do
            TYPE=\$(jq -r '.type // \"\"' \"\$f\" 2>/dev/null)
            if [ \"\$TYPE\" != \"JSON\" ]; then continue; fi
            FROM=\$(jq -r '.from // \"\"' \"\$f\" 2>/dev/null)
            DATA=\$(jq -r '.data // \"\"' \"\$f\" 2>/dev/null)
            OP=\$(echo \"\$DATA\" | jq -r '.op // \"\"' 2>/dev/null)
            REQ=\$(echo \"\$DATA\" | jq -r '.req // \"\"' 2>/dev/null)
            if [ \"\$OP\" != \"mul\" ] || [ -z \"\$REQ\" ] || [ -z \"\$FROM\" ]; then continue; fi
            echo \"\$(date +%H:%M:%S.%N) respond req=\$REQ from=\$FROM\" >> /tmp/responder.log
            pilotctl --json send-message \"\$FROM\" --data \"mul:\$REQ:${MULTIPLIER}\" --type text >>/tmp/responder.log 2>&1 || true
            rm -f \"\$f\"
        done
        sleep 0.1
    done
    echo responder-exit >> /tmp/responder.log
"
sleep 1
log_pass "responder running"

# ----- 2. Start the task-worker on agent-b that chains through the responder -----
# For every NEW task description "compute:<N>":
#   - accept it
#   - generate a request id REQ = TID (shortened), send JSON {req,op:"mul"}
#     to the submitter
#   - poll our OWN inbox for a text reply "mul:<REQ>:<M>"
#   - compute N*M, send-results "result:<N*M>"
# Crucially, the worker MUST only consume the mul reply that matches ITS
# current req — any other reply must stay in-inbox for the other task.
log_test "start task-message worker on agent-b"
$DC exec -d agent-b bash -c "
    rm -f /tmp/worker.log /tmp/worker_stop
    INBOX=/root/.pilot/inbox
    while [ ! -f /tmp/worker_stop ]; do
        LIST=\$(pilotctl --json task list --type received 2>/dev/null)
        for TID in \$(echo \"\$LIST\" | jq -r '.data.tasks[]? | select(.status == \"NEW\") | .task_id'); do
            DESC=\$(echo \"\$LIST\" | jq -r --arg t \"\$TID\" '.data.tasks[] | select(.task_id == \$t) | .description')
            # parse N out of 'compute:<N>'
            N=\$(echo \"\$DESC\" | awk -F: '{print \$2}')
            REQ=\"r-\${TID:0:8}\"
            SUBMITTER=\$(echo \"\$LIST\" | jq -r --arg t \"\$TID\" '.data.tasks[] | select(.task_id == \$t) | (.submitter_address // .from // \"\")')
            if [ -z \"\$SUBMITTER\" ]; then SUBMITTER=\"agent-a\"; fi
            echo \"\$(date +%H:%M:%S.%N) accept tid=\$TID n=\$N req=\$REQ\" >> /tmp/worker.log
            pilotctl task accept --id \"\$TID\" >>/tmp/worker.log 2>&1 || true

            # Send the helper request.
            pilotctl send-message \"\$SUBMITTER\" --data \"{\\\"req\\\":\\\"\$REQ\\\",\\\"op\\\":\\\"mul\\\"}\" --type json >>/tmp/worker.log 2>&1 || true

            # Poll inbox for matching reply; must NOT eat replies for other reqs.
            M=\"\"
            for _ in \$(seq 1 60); do
                for f in \$(ls -1 \$INBOX/*.json 2>/dev/null); do
                    TP=\$(jq -r '.type // \"\"' \"\$f\" 2>/dev/null)
                    DA=\$(jq -r '.data // \"\"' \"\$f\" 2>/dev/null)
                    case \"\$DA\" in
                        mul:\$REQ:*)
                            if [ \"\$TP\" = \"TEXT\" ]; then
                                M=\$(echo \"\$DA\" | awk -F: '{print \$3}')
                                rm -f \"\$f\"
                                break 2
                            fi
                            ;;
                    esac
                done
                sleep 0.2
            done

            if [ -z \"\$M\" ]; then
                echo \"\$(date +%H:%M:%S.%N) NO REPLY for req=\$REQ\" >> /tmp/worker.log
                pilotctl task send-results --id \"\$TID\" --results \"no-multiplier\" >>/tmp/worker.log 2>&1 || true
                continue
            fi

            RESULT=\$((N * M))
            echo \"\$(date +%H:%M:%S.%N) compute tid=\$TID n=\$N mul=\$M result=\$RESULT\" >> /tmp/worker.log
            pilotctl task send-results --id \"\$TID\" --results \"result:\$RESULT\" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.15
    done
    echo worker-exit >> /tmp/worker.log
"
sleep 1
log_pass "worker running"

# ----- 3. agent-a submits two concurrent tasks -----
log_test "agent-a submits two tasks in parallel: compute:3, compute:5"
RES1=$(mktemp)
RES2=$(mktemp)
$DC exec -T agent-a pilotctl --json task submit agent-b --task "compute:3" >"$RES1" 2>&1 &
$DC exec -T agent-a pilotctl --json task submit agent-b --task "compute:5" >"$RES2" 2>&1 &
wait
TID3=$(jq -r '.data.task_id // empty' <"$RES1")
TID5=$(jq -r '.data.task_id // empty' <"$RES2")
ACC3=$(jq -r '.data.accepted' <"$RES1")
ACC5=$(jq -r '.data.accepted' <"$RES2")
rm -f "$RES1" "$RES2"

if [ "$ACC3" = "true" ] && [ -n "$TID3" ] && [ "$ACC5" = "true" ] && [ -n "$TID5" ]; then
    log_pass "submitted: compute:3 -> $TID3, compute:5 -> $TID5"
else
    log_fail "submit rejected: compute:3(acc=$ACC3) compute:5(acc=$ACC5)"
    # Most likely cause = polo gate; in that case just run one task as a sanity fallback.
    exit 1
fi

# ----- 4. Both tasks reach COMPLETED on submitter -----
log_test "both tasks reach COMPLETED on agent-a within 45s"
wait_done() {
    local tid=$1
    for _ in $(seq 1 45); do
        local s
        s=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$s" | grep -qiE "completed|succeeded|done"; then
            echo "$s"; return 0
        fi
        sleep 1
    done
    echo "$s"; return 1
}
ST3=$(wait_done "$TID3")
ST5=$(wait_done "$TID5")
if echo "$ST3" | grep -qiE "completed|succeeded|done" && echo "$ST5" | grep -qiE "completed|succeeded|done"; then
    log_pass "compute:3=$ST3  compute:5=$ST5"
else
    log_fail "incomplete: compute:3=$ST3 compute:5=$ST5"
    echo "  worker log:"
    $DC exec -T agent-b tail -40 /tmp/worker.log 2>&1 | sed 's/^/    /'
    echo "  responder log:"
    $DC exec -T agent-a tail -20 /tmp/responder.log 2>&1 | sed 's/^/    /'
fi

# ----- 5. Results correlate: compute:3 → result:21, compute:5 → result:35 -----
log_test "results correlate to the correct N (3*7=21, 5*7=35)"
R3=$($DC exec -T agent-a pilotctl --json task result "$TID3" 2>&1 | jq -r '.data.content // empty')
R5=$($DC exec -T agent-a pilotctl --json task result "$TID5" 2>&1 | jq -r '.data.content // empty')
if [ "$R3" = "result:21" ] && [ "$R5" = "result:35" ]; then
    log_pass "compute:3->$R3  compute:5->$R5"
else
    log_fail "mismatched results: compute:3=\"$R3\" compute:5=\"$R5\""
fi

# ----- 6. Responder processed exactly 2 mul requests -----
log_test "responder handled exactly 2 mul requests (one per task)"
RESP_CNT=$($DC exec -T agent-a bash -c "grep -c 'respond req=' /tmp/responder.log 2>/dev/null || echo 0")
if [ "$RESP_CNT" = "2" ]; then
    log_pass "responder handled 2 requests"
else
    log_fail "responder handled $RESP_CNT requests (expected 2)"
    $DC exec -T agent-a tail -30 /tmp/responder.log 2>&1 | sed 's/^/    /'
fi

# ----- 7. Worker log shows the correct multiplier for each request -----
log_test "worker log shows mul=$MULTIPLIER for both tasks"
MUL_CNT=$($DC exec -T agent-b bash -c "grep -c 'mul=$MULTIPLIER' /tmp/worker.log 2>/dev/null || echo 0")
if [ "$MUL_CNT" = "2" ]; then
    log_pass "worker read multiplier twice"
else
    log_fail "worker read multiplier $MUL_CNT times (expected 2)"
    $DC exec -T agent-b tail -40 /tmp/worker.log 2>&1 | sed 's/^/    /'
fi

# ----- 8. agent-b's inbox: no stray mul-replies left over -----
# If correlation worked, each worker iteration consumed exactly its own
# reply; if it broke, we'd see left-over "mul:" messages here.
log_test "agent-b inbox has no stray mul: replies"
B_IN=$($DC exec -T agent-b pilotctl --json inbox 2>/dev/null)
STRAY=$(echo "$B_IN" | jq -r '[.data.messages[]? | select(.data | startswith("mul:"))] | length' 2>/dev/null)
if [ "$STRAY" = "0" ]; then
    log_pass "inbox clean (no stray mul: replies)"
else
    log_fail "$STRAY stray mul: replies in agent-b inbox"
    echo "$B_IN" | jq -r '.data.messages[]? | select(.data | startswith("mul:")) | "  \(.data)"'
fi

# ----- 9. No panic/fatal in either daemon log -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

# Cleanup
$DC exec -T agent-a touch /tmp/responder_stop >/dev/null 2>&1
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1

echo
echo "=========================================="
echo "Task-message chain test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
