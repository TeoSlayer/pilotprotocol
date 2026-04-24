#!/bin/bash
# Observability: `pilotctl task list` matches the on-disk JSON files 1:1.
# On the receiver (agent-b), tasks are persisted at
# $HOME/.pilot/tasks/received/<task_id>.json. After N submits, the output
# of `pilotctl --json task list --type received` must have exactly the same
# task_id set as the JSON filenames in that directory, with identical
# status fields.

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
N=4

cd "$(dirname "$0")" || exit 1
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

log_test "submit $N tasks a->b (no worker — stay in NEW)"
SUBMITTED_IDS=()
for i in $(seq 1 "$N"); do
    OUT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "disk-$i" 2>&1)
    TID=$(echo "$OUT" | jq -r '.data.task_id // empty')
    [ -n "$TID" ] || { log_fail "submit $i failed"; exit 1; }
    SUBMITTED_IDS+=("$TID")
done
log_pass "submitted $N tasks: ${SUBMITTED_IDS[*]}"
sleep 3

# --- CLI view ---
CLI_JSON=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null)
CLI_IDS=$(echo "$CLI_JSON" | jq -r '.data.tasks[]?.task_id' | sort -u)
CLI_COUNT=$(echo "$CLI_IDS" | grep -c . || true)
log_test "CLI reports $CLI_COUNT received tasks"

# --- Disk view ---
DISK_IDS=$($DC exec -T agent-b bash -c 'ls /root/.pilot/tasks/received/ 2>/dev/null | sed "s/\.json$//"' | sort -u)
DISK_COUNT=$(echo "$DISK_IDS" | grep -c . || true)
log_test "Disk has $DISK_COUNT .json files in tasks/received/"

# Must be equal in count.
if [ "$CLI_COUNT" = "$DISK_COUNT" ] && [ "$CLI_COUNT" = "$N" ]; then
    log_pass "count match: CLI=$CLI_COUNT disk=$DISK_COUNT (both = $N)"
else
    log_fail "count mismatch: CLI=$CLI_COUNT disk=$DISK_COUNT (expected $N)"
fi

# Must be the same set of IDs.
DIFF=$(diff <(echo "$CLI_IDS") <(echo "$DISK_IDS"))
if [ -z "$DIFF" ]; then
    log_pass "task_id set matches 1:1"
else
    log_fail "task_id set diff:\n$DIFF"
fi

# Per-task status: CLI status must equal status field in the on-disk JSON.
log_test "status agrees per-task"
FAIL_STATUS=0
for TID in $CLI_IDS; do
    [ -z "$TID" ] && continue
    CLI_ST=$(echo "$CLI_JSON" | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    DISK_ST=$($DC exec -T agent-b bash -c "cat /root/.pilot/tasks/received/$TID.json" 2>/dev/null | jq -r '.status // empty')
    if [ -z "$DISK_ST" ]; then
        # .status may be nested differently; try common alt paths.
        DISK_ST=$($DC exec -T agent-b bash -c "cat /root/.pilot/tasks/received/$TID.json" 2>/dev/null | jq -r '.task_status // .Status // empty')
    fi
    if [ "$CLI_ST" != "$DISK_ST" ]; then
        echo "   mismatch $TID: cli=$CLI_ST disk=$DISK_ST"
        FAIL_STATUS=$((FAIL_STATUS + 1))
    fi
done
if [ "$FAIL_STATUS" -eq 0 ]; then log_pass "per-task status agrees"; else log_fail "$FAIL_STATUS status mismatches"; fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
