#!/bin/bash
# Fan-in: agent-b and agent-c concurrently submit tasks to agent-a.
# agent-a runs one worker that must handle both submitters correctly.
#
# Proves:
#   - receiver can interleave tasks from multiple submitters without mixing
#     up task-ids, submitter addresses, or result routing.
#   - neither submitter is starved.

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
echo "Fan-in: b & c submit to a concurrently"
echo "=========================================="

log_test "Starting 3-agent stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "3 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

for s in agent-a agent-b agent-c; do
    $DC exec -T $s pilotctl enable-tasks >/dev/null 2>&1
done

# Worker on agent-a that accepts and echoes: "ack:<desc>".
# Uses /tmp/worker_start as a gate so the worker doesn't begin
# processing until AFTER all 8 fan-in submits have landed in the
# receiver queue. Without this, the polo gate (decremented on each
# completion) starts rejecting subsequent submits mid-burst.
log_test "start worker on agent-a (gated until burst lands)"
$DC exec -d agent-a bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log /tmp/worker_start
    while [ ! -f /tmp/worker_start ]; do sleep 0.1; done
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "ack:$DESC" >>/tmp/worker.log 2>&1 || true
            echo "$(date +%H:%M:%S.%N) done tid=$TID desc=$DESC" >> /tmp/worker.log
        done
        sleep 0.2
    done
'
sleep 1
log_pass "worker running"

# Fire b and c in parallel, each submitting 4 tasks.
log_test "b and c each submit 4 tasks concurrently"
RES_B=$(mktemp)
RES_C=$(mktemp)
(
    for i in 1 2 3 4; do
        $DC exec -T agent-b pilotctl --json task submit agent-a --task "from-b:$i" >>"$RES_B" 2>&1
    done
) &
BPID=$!
(
    for i in 1 2 3 4; do
        $DC exec -T agent-c pilotctl --json task submit agent-a --task "from-c:$i" >>"$RES_C" 2>&1
    done
) &
CPID=$!
wait $BPID $CPID

# All 8 submits have landed; release the worker.
$DC exec -T agent-a touch /tmp/worker_start >/dev/null 2>&1

B_TIDS=$(jq -r '.data.task_id' <"$RES_B" | grep -v '^$' | sort -u)
C_TIDS=$(jq -r '.data.task_id' <"$RES_C" | grep -v '^$' | sort -u)
NB=$(echo "$B_TIDS" | grep -c .)
NC_=$(echo "$C_TIDS" | grep -c .)

if [ "$NB" = "4" ] && [ "$NC_" = "4" ]; then
    log_pass "b submitted $NB, c submitted $NC_"
else
    log_fail "submit counts wrong: b=$NB c=$NC_"
fi

# Wait for all 8 to complete on the respective submitter.
wait_all() {
    local role=$1 tids=$2
    for tid in $tids; do
        for _ in $(seq 1 45); do
            s=$($DC exec -T "agent-$role" pilotctl --json task list --type submitted 2>/dev/null \
                | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status')
            if echo "$s" | grep -qiE "completed|succeeded|done"; then break; fi
            sleep 1
        done
        if ! echo "$s" | grep -qiE "completed|succeeded|done"; then
            echo "stuck:$tid:$s"
            return 1
        fi
    done
    return 0
}

log_test "all 8 submitted tasks reach COMPLETED"
if wait_all b "$B_TIDS" && wait_all c "$C_TIDS"; then
    log_pass "all 8 tasks completed"
else
    log_fail "one or more tasks stuck"
    $DC exec -T agent-a tail -60 /tmp/worker.log 2>&1 | sed 's/^/  a-worker: /'
fi

# Verify result correctness (each submitter gets their own result).
log_test "each submitter gets its own ack:* result"
mismatches=0
for role in b c; do
    # ${role^^} is bash-4 only; macOS bash 3.2 doesn't have it. Use tr.
    rolevar="$(echo "$role" | tr '[:lower:]' '[:upper:]')_TIDS"
    for tid in $(eval echo "\${$rolevar}"); do
        RES=$($DC exec -T "agent-$role" pilotctl --json task result "$tid" 2>/dev/null \
            | jq -r '.data.content // empty')
        case "$RES" in
            ack:from-$role:*) ;;
            *) echo "  mismatch role=$role tid=$tid result=$RES"; mismatches=$((mismatches+1)) ;;
        esac
    done
done
if [ "$mismatches" = "0" ]; then
    log_pass "results correctly routed to each submitter"
else
    log_fail "$mismatches mis-routed results"
fi

log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b agent-c 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

rm -f "$RES_B" "$RES_C"
$DC exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1
$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Fan-in tasks summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
