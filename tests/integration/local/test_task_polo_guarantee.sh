#!/bin/bash
# Polo guarantee floor: receivers can publish a min_polo requirement
# (Daemon.Config.PoloGateMin). The registry's authorize_task_submit
# rejects any submitter whose polo is below the floor — even if the
# receiver itself scores lower.
#
# Note: at present the floor is configured statically per daemon. This
# test exercises the rejection path; once the floor is tunable at
# runtime we can extend it.

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

# Establish a polo gradient so a.polo == 0 < b.polo (after first submit
# completes). With the default rule (submitter polo >= receiver polo),
# the second a->b submit gets rejected — proving the gate is live.
log_test "polo gate (default rule) rejects second submit a->b"
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1
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
sleep 1

# First submit succeeds (both polo == 0).
S=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "establish" 2>&1)
TID=$(echo "$S" | jq -r '.data.task_id // empty')
[ -n "$TID" ] || { log_fail "first submit rejected: $S"; exit 1; }
for _ in $(seq 1 30); do
    ST=$($DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$TID" '.data.tasks[]? | select(.task_id == $t) | .status')
    echo "$ST" | grep -qiE "completed|succeeded|done" && break
    sleep 1
done
sleep 1

S2=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "should-reject" 2>&1)
ACC2=$(echo "$S2" | jq -r '.data.accepted')
MSG2=$(echo "$S2" | jq -r '.data.message // .message // empty')
if [ "$ACC2" = "false" ] && echo "$MSG2" | grep -qiE "polo|score"; then
    log_pass "rejected with polo-cited message: $MSG2"
else
    log_fail "expected rejection citing polo, got accepted=$ACC2 msg=$MSG2"
fi

# Privacy check: the rejection message must NOT leak either side's polo.
log_test "rejection message does NOT leak any polo score values"
if echo "$MSG2" | grep -qE "submitter=[0-9]|receiver=[0-9]|polo=[0-9]"; then
    log_fail "POLO LEAK in rejection message: $MSG2"
else
    log_pass "no polo numbers leaked in reason: $MSG2"
fi

log_test "self-read: pilotctl my-polo returns a value"
SELF=$($DC exec -T agent-a pilotctl --json my-polo 2>/dev/null | jq -r '.data.polo_score // empty')
if [ -n "$SELF" ] && [ "$SELF" != "null" ]; then
    log_pass "agent-a self-read polo=$SELF"
else
    log_fail "self-read failed; got: $SELF"
fi

echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
