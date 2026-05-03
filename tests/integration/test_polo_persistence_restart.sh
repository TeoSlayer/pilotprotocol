#!/bin/bash
# Matrix 2 F-series: polo score survives daemon restart.
#
# Polo scores are held on the REGISTRY, not the agent daemon. So
# "persistence across restart" means:
#   1. Starting state: a.polo = b.polo = 0.
#   2. a submits T1 to b, T1 completes. This mutates both polo scores
#      (a.polo goes negative, b.polo goes positive — see polo gate spec).
#   3. Restart the rendezvous service.
#   4. After rendezvous comes back, pilotctl lookup on each node's
#      node_id must return the SAME polo scores.
#
# If polo scores are only in-memory, this test will expose it.

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
echo "Polo score persistence across restart"
echo "=========================================="

cleanup() {
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1 || true
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
[ "$COUNT" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "agents up"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Get node IDs
NID_A=$($DC exec -T agent-a pilotctl --json info 2>/dev/null | jq -r '.data.node_id')
NID_B=$($DC exec -T agent-b pilotctl --json info 2>/dev/null | jq -r '.data.node_id')
[ -n "$NID_A" ] && [ -n "$NID_B" ] || { log_fail "could not read node_ids"; exit 1; }

# Auto-accept worker on b
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop /tmp/worker.log
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >>/tmp/worker.log 2>&1 || true
            pilotctl task send-results --id "$TID" --results "polo-ok" >>/tmp/worker.log 2>&1 || true
        done
        sleep 0.25
    done
'

# Submit + complete T1 to move the polo needle.
log_test "submit+complete T1 to mutate polo"
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "polo-task" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "submit failed"; exit 1; }
for _ in $(seq 1 45); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    if echo "$ST" | grep -qiE "completed|succeeded|done"; then break; fi
    sleep 1
done
echo "$ST" | grep -qiE "completed|succeeded|done" || { log_fail "T1 never completed (status=$ST)"; exit 1; }
log_pass "T1 completed"

# Snapshot polo scores pre-restart.
POLO_A_PRE=$($DC exec -T agent-a pilotctl --json lookup "$NID_A" 2>/dev/null | jq -r '.data.node.polo_score // .data.polo_score // empty')
POLO_B_PRE=$($DC exec -T agent-b pilotctl --json lookup "$NID_B" 2>/dev/null | jq -r '.data.node.polo_score // .data.polo_score // empty')
echo "    pre-restart polo: a=$POLO_A_PRE b=$POLO_B_PRE"

if [ -z "$POLO_A_PRE" ] || [ -z "$POLO_B_PRE" ]; then
    log_fail "could not read polo_score from lookup output"
    exit 1
fi

# Restart rendezvous (polo lives there).
log_test "restart rendezvous service"
$DC restart rendezvous >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    if [ "$COUNT" -ge 2 ]; then break; fi
    sleep 1
done
if [ "$COUNT" -ge 2 ]; then
    log_pass "rendezvous back, $COUNT agents visible"
else
    log_fail "rendezvous did not come back"
    exit 1
fi

# Re-read polo scores.
POLO_A_POST=$($DC exec -T agent-a pilotctl --json lookup "$NID_A" 2>/dev/null | jq -r '.data.node.polo_score // .data.polo_score // empty')
POLO_B_POST=$($DC exec -T agent-b pilotctl --json lookup "$NID_B" 2>/dev/null | jq -r '.data.node.polo_score // .data.polo_score // empty')
echo "    post-restart polo: a=$POLO_A_POST b=$POLO_B_POST"

log_test "polo scores survived rendezvous restart"
if [ "$POLO_A_PRE" = "$POLO_A_POST" ] && [ "$POLO_B_PRE" = "$POLO_B_POST" ]; then
    log_pass "scores preserved exactly"
else
    log_fail "scores changed across restart: a $POLO_A_PRE->$POLO_A_POST, b $POLO_B_PRE->$POLO_B_POST"
fi

log_test "no panic/fatal"
BAD=$($DC logs agent-a agent-b rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "$BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
