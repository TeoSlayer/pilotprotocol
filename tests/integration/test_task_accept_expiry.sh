#!/bin/bash
# Task accept-timeout expiry: a task left NEW for more than the 1-minute
# TaskAcceptTimeout should be auto-cancelled by each daemon's
# monitorNewTasksForCancellation goroutine (10s ticker). Both sides must
# converge to CANCELLED without any explicit accept/decline.
#
# Failure modes this catches:
#  - the 10s ticker never fires / is not started at boot (would leave the
#    task stuck NEW forever)
#  - only one side updates (CancelTaskBothSides only writes local files —
#    both daemons must independently detect and cancel their own copy)
#  - accept after expiry returns a wrong/missing error
#  - polo is (incorrectly) charged for an un-accepted task — a fresh T2
#    submit must still succeed after T1 expires

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
echo "Task accept-expiry integration"
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

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1

receiver_status() {
    $DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null \
        | jq -r --arg t "$1" '.data.tasks[]? | select(.task_id == $t) | .status'
}
submitter_status() {
    $DC exec -T agent-a pilotctl --json task list --type submitted 2>/dev/null \
        | jq -r --arg t "$1" '.data.tasks[]? | select(.task_id == $t) | .status'
}

# ----- 1. Submit T1; leave it NEW (no accept, no decline) -----
log_test "agent-a submits T1 (will be left to expire)"
S1=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "please-ignore-me" 2>&1)
TID=$(echo "$S1" | jq -r '.data.task_id // empty')
if [ -n "$TID" ]; then
    log_pass "T1: $TID"
else
    log_fail "T1 submit failed: $(echo "$S1" | head -c 200)"
    exit 1
fi

log_test "T1 is NEW on both sides before expiry"
R0=$(receiver_status "$TID")
S0=$(submitter_status "$TID")
if [ "$R0" = "NEW" ] && [ "$S0" = "NEW" ]; then
    log_pass "receiver=NEW submitter=NEW"
else
    log_fail "wrong initial state: receiver=$R0 submitter=$S0"
fi

# ----- 2. Wait for both auto-cancel tickers to fire past 1m timeout -----
# Accept timeout = 60s, ticker = 10s, + network / disk jitter.
# Poll every 5s up to 110s total.
log_test "wait for auto-cancellation (up to ~110s)"
R=""
S=""
ELAPSED=0
for i in $(seq 1 22); do
    sleep 5
    ELAPSED=$((ELAPSED+5))
    R=$(receiver_status "$TID")
    S=$(submitter_status "$TID")
    if [ "$R" = "CANCELLED" ] && [ "$S" = "CANCELLED" ]; then
        log_pass "both sides CANCELLED after ~${ELAPSED}s"
        break
    fi
done
if [ "$R" != "CANCELLED" ] || [ "$S" != "CANCELLED" ]; then
    log_fail "did not converge: receiver=$R submitter=$S (elapsed=${ELAPSED}s)"
fi

# ----- 3. Accept after expiry must fail (task is no longer NEW) -----
log_test "accept after expiry is rejected"
ACC=$($DC exec -T agent-b pilotctl --json task accept --id "$TID" 2>&1)
CODE=$(echo "$ACC" | jq -r '.code // empty')
if [ "$CODE" = "invalid_state" ] || [ "$CODE" = "expired" ]; then
    log_pass "accept rejected (code=$CODE)"
else
    log_fail "unexpected accept response: $(echo "$ACC" | head -c 200)"
fi

# ----- 4. Decline after expiry must fail (task is no longer NEW) -----
log_test "decline after expiry is rejected"
DEC=$($DC exec -T agent-b pilotctl --json task decline --id "$TID" --justification "already-expired" 2>&1)
if echo "$DEC" | grep -qE "invalid_state|already CANCELLED|not NEW"; then
    log_pass "decline rejected"
else
    log_fail "unexpected decline response: $(echo "$DEC" | head -c 200)"
fi

# ----- 5. Fresh T2 works: expiry must not have charged polo -----
log_test "fresh submit after expiry still allowed (polo unchanged)"
S2=$($DC exec -T agent-a pilotctl --json task submit agent-b --task "post-expiry" 2>&1)
TID2=$(echo "$S2" | jq -r '.data.task_id // empty')
ACC2=$(echo "$S2" | jq -r '.data.accepted')
if [ "$ACC2" = "true" ] && [ -n "$TID2" ]; then
    log_pass "T2 submitted: $TID2"
else
    log_fail "T2 rejected (accepted=$ACC2): $(echo "$S2" | head -c 200)"
fi

# Quickly complete T2 so we leave the daemon in a clean state.
if [ -n "$TID2" ]; then
    $DC exec -T agent-b pilotctl task accept --id "$TID2" >/dev/null 2>&1
    $DC exec -T agent-b pilotctl task send-results --id "$TID2" --results "ok" >/dev/null 2>&1
fi

# ----- 6. No panics/fatals across the whole expiry window -----
log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "=========================================="
echo "Task accept-expiry test summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
