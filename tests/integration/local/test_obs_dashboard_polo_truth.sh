#!/bin/bash
# Polo truth via observable gate behavior.
#
# Polo is private — clients can't read scores. Instead we verify polo
# bookkeeping by observing the gate's behavior:
#   - Submit N tasks a->b. Each completion bumps b.polo positive and
#     a.polo negative.
#   - After N completions, a.polo < b.polo, so a follow-up submit a->b
#     MUST be rejected by the polo gate.
#   - A submit b->a (where submitter has the higher polo) MUST succeed.
#
# This validates that completed tasks did mutate polo on the registry —
# without exposing the underlying scores to the client.

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
N_TASKS=5

cd "$(dirname "$0")" || exit 1
cleanup() {
    $DC exec -T agent-a touch /tmp/worker_stop >/dev/null 2>&1 || true
    $DC exec -T agent-b touch /tmp/worker_stop >/dev/null 2>&1 || true
    $DC down -v >/dev/null 2>&1
}
trap cleanup EXIT

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "${COUNT:-0}" -ge 2 ] || { log_fail "agents did not register"; exit 1; }
log_pass "both agents registered"

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

# Worker on agent-b (auto-accept everything)
$DC exec -d agent-b bash -c '
    rm -f /tmp/worker_stop
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >/dev/null 2>&1 || true
            pilotctl task send-results --id "$TID" --results "ok" >/dev/null 2>&1 || true
        done
        sleep 0.3
    done
'

# Submit one task and wait — that establishes a polo gradient.
log_test "submit + complete 1 task a->b to establish polo gradient"
OUT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "polo-establish" 2>&1)
TID=$(echo "$OUT" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "first submit failed: $OUT"; exit 1; }
for _ in $(seq 1 30); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    echo "$ST" | grep -qiE "completed|succeeded|done" && break
    sleep 1
done
echo "$ST" | grep -qiE "completed|succeeded|done" || { log_fail "first task never completed"; exit 1; }
sleep 1
log_pass "polo gradient established (a < b)"

# After the gradient is set, a->b should now be rejected.
log_test "follow-up a->b must be rejected (gate sees a.polo < b.polo)"
OUT=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "should-reject" 2>&1)
ACC=$(echo "$OUT" | jq -r '.data.accepted')
if [ "$ACC" = "false" ]; then
    log_pass "polo gate fired — proves polo was mutated by previous completion"
else
    log_fail "follow-up unexpectedly accepted — polo not mutated: $OUT"
fi

# And b->a should succeed (submitter has higher polo).
log_test "reverse b->a must be allowed (gate sees b.polo >= a.polo)"
$DC exec -T agent-a pilotctl enable-tasks >/dev/null 2>&1
$DC exec -d agent-a bash -c '
    rm -f /tmp/worker_stop
    while [ ! -f /tmp/worker_stop ]; do
        LIST=$(pilotctl --json task list --type received 2>/dev/null)
        for TID in $(echo "$LIST" | jq -r ".data.tasks[]? | select(.status == \"NEW\") | .task_id"); do
            pilotctl task accept --id "$TID" >/dev/null 2>&1 || true
            pilotctl task send-results --id "$TID" --results "ack" >/dev/null 2>&1 || true
        done
        sleep 0.3
    done
'
sleep 1
OUT=$($DC exec -T agent-b pilotctl --json task submit agent-a --task "reverse" 2>&1)
ACC=$(echo "$OUT" | jq -r '.data.accepted')
[ "$ACC" = "true" ] && log_pass "reverse direction allowed" || log_fail "reverse direction rejected: $OUT"

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
