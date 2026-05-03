#!/bin/bash
# Star-5 hub fan-in: all 4 leaves submit tasks to the hub concurrently.
# Hub's worker accepts and echoes all of them. Proves the hub can handle
# simultaneous connections from all leaves without dropping anything.

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

DC="docker compose -f docker-compose.star5hub.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

echo "=========================================="
echo "Star-5 hub fan-in"
echo "=========================================="

log_test "Starting star stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous hub leaf-1 leaf-2 leaf-3 leaf-4 >/dev/null 2>&1
if COUNT=$(wait_all_registered 5 rendezvous); then
    log_pass "5 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

for s in hub leaf-1 leaf-2 leaf-3 leaf-4; do
    $DC exec -T $s pilotctl enable-tasks >/dev/null 2>&1
done

# Hub worker: echoes "hub-ack:<desc>"
log_test "start hub worker"
$DC exec -d hub bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            DESC=$(echo "$LIST" | jq -r --arg t "$TID" ".data.tasks[] | select(.task_id == \$t) | .description")
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "hub-ack:$DESC" >>/tmp/worker.log 2>&1 || true
            echo "$(date +%H:%M:%S.%N) done tid=$TID" >> /tmp/worker.log
        done
        sleep 0.2
    done
'
sleep 1
log_pass "hub worker running"

log_test "4 leaves submit to hub concurrently"
TMP=$(mktemp -d)
for i in 1 2 3 4; do
    $DC exec -T "leaf-$i" pilotctl --json task submit hub --task "from-leaf-$i" >"$TMP/$i" 2>&1 &
done
wait

TIDS=""
for i in 1 2 3 4; do
    tid=$(jq -r '.data.task_id // empty' <"$TMP/$i")
    if [ -z "$tid" ]; then
        log_fail "leaf-$i could not submit: $(cat "$TMP/$i" | head -c 200)"
    fi
    TIDS="$TIDS leaf-$i:$tid"
done
log_pass "submissions: $TIDS"

log_test "all 4 leaf tasks reach COMPLETED"
FAIL=0
for i in 1 2 3 4; do
    tid=$(jq -r '.data.task_id // empty' <"$TMP/$i")
    [ -z "$tid" ] && { FAIL=$((FAIL+1)); continue; }
    ST=""
    for _ in $(seq 1 45); do
        ST=$($DC exec -T "leaf-$i" pilotctl --json task list --type submitted 2>/dev/null \
            | jq -r --arg t "$tid" '.data.tasks[]? | select(.task_id == $t) | .status')
        if echo "$ST" | grep -qiE "completed|succeeded|done"; then break; fi
        sleep 1
    done
    if ! echo "$ST" | grep -qiE "completed|succeeded|done"; then
        echo "  leaf-$i stuck at $ST"
        FAIL=$((FAIL+1))
    fi
done
if [ "$FAIL" = "0" ]; then
    log_pass "all 4 completed"
else
    log_fail "$FAIL/4 stuck"
fi

log_test "each leaf got its own hub-ack:from-leaf-N result"
OK=0
for i in 1 2 3 4; do
    tid=$(jq -r '.data.task_id // empty' <"$TMP/$i")
    [ -z "$tid" ] && continue
    RES=$($DC exec -T "leaf-$i" pilotctl --json task result "$tid" 2>/dev/null \
        | jq -r '.data.content // empty')
    if [ "$RES" = "hub-ack:from-leaf-$i" ]; then
        OK=$((OK+1))
    else
        echo "  leaf-$i got '$RES'"
    fi
done
if [ "$OK" = "4" ]; then
    log_pass "all 4 results routed correctly"
else
    log_fail "$OK/4 results correct"
fi

log_test "no panics/fatals"
BAD=$($DC logs 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

rm -rf "$TMP"
$DC exec -T hub touch /tmp/worker_stop >/dev/null 2>&1
$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Star-5 fan-in summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
