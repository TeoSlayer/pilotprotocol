#!/bin/bash
# Three-agent task forwarding chain: a submits a task to b; b cannot complete
# it alone, so b submits a sub-task to c; c returns a result to b; b returns
# the final result to a.
#
# Proves:
#   - A single daemon can be both a task submitter and a task receiver
#     concurrently (b's role).
#   - Task IDs and submitter addresses stay correct across a two-hop chain.
#   - a never sees c directly — only the final result comes back.

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

DC="docker compose -f docker-compose.multi3.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Chain a->b->c task forwarding"
echo "=========================================="

log_test "Starting 3-agent stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "all 3 agents registered (total_nodes=$COUNT)"
else
    log_fail "agents did not register in time (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
$DC exec -T agent-c pilotctl enable-tasks >/dev/null 2>&1

# ----- Worker on agent-c: doubles whatever N arrives ------------------
log_test "start leaf worker on agent-c (N -> 2N)"
$DC exec -d agent-c bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            N=$(echo "$DESC" | awk -F: "{print \$2}")
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            OUT=$((N * 2))
            pilotctl task send-results --id "$TID" --results "leaf:$OUT" >>/tmp/worker.log 2>&1 || true
            echo "$(date +%H:%M:%S.%N) leaf done tid=$TID N=$N out=$OUT" >> /tmp/worker.log
        done
        sleep 0.2
    done
'
sleep 1
log_pass "leaf worker running"

# ----- Worker on agent-b: forward to c, wrap result ------------------
log_test "start middle worker on agent-b (forwards compute:N -> agent-c sub:N, then reports wrapped)"
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            case "$DESC" in
                compute:*) ;;
                *) continue ;;
            esac
            N=$(echo "$DESC" | awk -F: "{print \$2}")
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            # Submit sub-task to c and wait for result.
            SUB=$(pilotctl --json task submit agent-c --task "sub:$N" 2>>/tmp/worker.log)
            STID=$(echo "$SUB" | jq -r ".data.task_id // empty")
            echo "$(date +%H:%M:%S.%N) mid forward parent=$TID sub=$STID" >> /tmp/worker.log
            FINAL=""
            for _ in $(seq 1 60); do
                ST=$(pilotctl --json task list --type submitted 2>/dev/null \
                    | jq -r --arg t "$STID" ".data.tasks[]? | select(.task_id == \$t) | .status")
                if echo "$ST" | grep -qiE "completed|succeeded|done"; then
                    FINAL=$(pilotctl --json task result "$STID" 2>/dev/null | jq -r ".data.content // empty")
                    break
                fi
                sleep 0.5
            done
            if [ -z "$FINAL" ]; then
                pilotctl task send-results --id "$TID" --results "mid:no-leaf-result" >>/tmp/worker.log 2>&1 || true
                continue
            fi
            # Pass it up wrapped so we can tell the hop happened.
            pilotctl task send-results --id "$TID" --results "mid:$FINAL" >>/tmp/worker.log 2>&1 || true
            echo "$(date +%H:%M:%S.%N) mid sent final=mid:$FINAL" >> /tmp/worker.log
        done
        sleep 0.25
    done
'
sleep 1
log_pass "middle worker running"

# ----- agent-a submits compute:5 -> expect final "mid:leaf:10" ----------
log_test "agent-a submits compute:5"
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "compute:5" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
ACC=$(echo "$S" | jq -r '.data.accepted')
if [ "$ACC" = "true" ] && [ -n "$TID" ]; then
    log_pass "submit accepted tid=$TID"
else
    log_fail "submit rejected: $S"
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
    $DC exec -T agent-c touch /tmp/worker_stop >/dev/null 2>&1
    $DC down -v >/dev/null 2>&1
    exit 1
fi

log_test "task reaches COMPLETED on agent-a within 60s"
ST=""
for _ in $(seq 1 60); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$ST" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
if echo "$ST" | grep -qiE "completed|succeeded|done"; then
    log_pass "completed (status=$ST)"
else
    log_fail "stuck at status=$ST"
    $DC exec -T agent-b tail -40 /tmp/worker.log 2>&1 | sed 's/^/  b: /'
    $DC exec -T agent-c tail -20 /tmp/worker.log 2>&1 | sed 's/^/  c: /'
fi

log_test "result is wrapped (mid:leaf:10) — proves two-hop chain"
R=$($DC exec -T agent-a pilotctl --json task result "$TID" 2>&1 | jq -r '.data.content // empty')
if [ "$R" = "mid:leaf:10" ]; then
    log_pass "chain result correct: $R"
else
    log_fail "unexpected result: $R"
fi

log_test "agent-a has no direct task to/from agent-c"
A_SUB=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null)
DIRECT=$(echo "$A_SUB" | jq -r '[.data.tasks[]? | select((.receiver_hostname // "") == "agent-c")] | length')
if [ "$DIRECT" = "0" ]; then
    log_pass "agent-a never directly talked to agent-c"
else
    log_fail "agent-a has $DIRECT direct tasks to agent-c"
fi

# Cleanup
$DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1
$DC exec -T agent-c touch /tmp/worker_stop >/dev/null 2>&1
$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Chain a->b->c task summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
