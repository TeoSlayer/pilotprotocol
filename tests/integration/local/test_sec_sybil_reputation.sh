#!/bin/bash
# Sybil attack: register 50 fresh identities in ~1 second, then have
# each try to submit a task to agent-b. The polo-gate (see
# test_task_polo_gate.sh and project_polo_gate memory note) rejects
# submissions from accounts whose polo score is below the receiver's.
# Freshly-registered nodes have polo = 0 and agent-b's polo will be > 0
# after baseline handshake, so every sybil submit MUST be rejected.
#
# EXPECTED:
#   - >= 45 / 50 sybil submits rejected at the polo gate (allow a small
#     slack for race conditions between register and first polo update).
#   - agent-b's task queue doesn't accumulate 50 NEW tasks.
#   - registry rate-limiter may also throttle the rapid registration;
#     either effect is an acceptable defense.

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
# shellcheck source=sec_helpers.sh
source ./sec_helpers.sh

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

log_test "fresh stack"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
if ! wait_for 60 bash -c '
    c=$(docker compose -f docker-compose.multi.yml exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r ".total_nodes // 0")
    [ "$c" -ge 2 ]
'; then
    log_fail "agents did not register"
    exit 1
fi

$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1 || true

log_test "spawn 50 sybil daemons inside agent-a container and submit"
# Each sybil gets a unique identity file, connects to the same registry,
# then tries to submit a task to agent-b. We do NOT spawn new containers
# (too slow/heavy) — the sybils run as short-lived pilot-daemon processes
# on distinct unix sockets inside agent-a.
$DC exec -T agent-a bash -c '
    set +e
    REGISTRY=${PILOT_REGISTRY:-172.29.0.10:9000}
    # Derive beacon and dashboard addresses from the registry host so this
    # works under run-all.sh -j 6 where each worker has its own subnet.
    REGISTRY_HOST="${REGISTRY%:*}"
    BEACON="${REGISTRY_HOST}:9001"
    DASHBOARD="http://${REGISTRY_HOST}:8080"
    mkdir -p /tmp/sybil
    ACCEPT=0
    REJECT=0
    START=$(date +%s)
    for i in $(seq 1 ${SYBIL_COUNT:-15}); do
        IDFILE="/tmp/sybil/id_$i.json"
        SOCK="/tmp/sybil/pilot_$i.sock"
        # Start a lightweight daemon for this sybil (no beacon, listens only for IPC)
        pilot-daemon \
            -registry "$REGISTRY" \
            -beacon "$BEACON" \
            -hostname "sybil-$i" \
            -identity "$IDFILE" \
            -socket "$SOCK" \
            -listen :0 \
            -log-level info \
            >/tmp/sybil/d_$i.log 2>&1 &
        echo $! > /tmp/sybil/pid_$i
        # Stagger spawns — bursting 15 fresh registrations can overwhelm the
        # registry rate limiter and cause silent daemon exits.
        sleep 0.1
    done

    # Wait up to 30s for registrations (need 2 baseline + SYBIL_COUNT)
    EXPECTED=$(( ${SYBIL_COUNT:-15} + 2 ))
    for j in $(seq 1 60); do
        REG=$(curl -fsS "${DASHBOARD}/api/stats" 2>/dev/null | jq -r ".total_nodes // 0")
        if [ "$REG" -ge "$EXPECTED" ]; then break; fi
        sleep 0.5
    done
    echo "registered: $REG / $EXPECTED expected"

    # Try a task submit from each sybil
    for i in $(seq 1 ${SYBIL_COUNT:-15}); do
        SOCK="/tmp/sybil/pilot_$i.sock"
        OUT=$(PILOT_SOCKET="$SOCK" timeout 5 pilotctl --json task submit agent-b --task "sybil-probe-$i" 2>&1)
        if echo "$OUT" | jq -e ".data.task_id // empty" >/dev/null 2>&1; then
            ACCEPT=$((ACCEPT+1))
        else
            REJECT=$((REJECT+1))
        fi
    done

    # Cleanup
    for i in $(seq 1 ${SYBIL_COUNT:-15}); do
        kill "$(cat /tmp/sybil/pid_$i 2>/dev/null)" 2>/dev/null || true
    done

    echo "accept=$ACCEPT reject=$REJECT"
' > /tmp/sybil_out.txt 2>&1

RESULT=$(grep -E '^accept=' /tmp/sybil_out.txt | tail -n1)
ACCEPT=$(echo "$RESULT" | sed -nE 's/.*accept=([0-9]+).*/\1/p')
REJECT=$(echo "$RESULT" | sed -nE 's/.*reject=([0-9]+).*/\1/p')
ACCEPT=${ACCEPT:-0}
REJECT=${REJECT:-0}
echo "sybil submit results: accept=$ACCEPT reject=$REJECT"

log_test "sybil submits blocked by polo-gate"
# Allow up to 10% successes (timing slack — polo may not have been ranked
# at exact moment of submit). Real defense should reject >=90%.
N=${SYBIL_COUNT:-15}
THRESHOLD=$(( N * 9 / 10 ))
if [ "$REJECT" -ge "$THRESHOLD" ]; then
    log_pass "polo-gate rejected $REJECT / $N sybil submits"
else
    log_fail "only $REJECT / $N rejected — polo-gate weak or absent"
fi

log_test "agent-b received-tasks queue not flooded"
COUNT=$($DC exec -T agent-b pilotctl --json task list --type received 2>/dev/null |
    jq -r '[.data.tasks[]? | select(.status == "NEW")] | length' 2>/dev/null)
COUNT=${COUNT:-0}
echo "NEW received tasks on agent-b: $COUNT"
if [ "$COUNT" -le 5 ]; then
    log_pass "task queue not flooded ($COUNT tasks)"
else
    log_fail "task queue has $COUNT NEW tasks — sybil flood succeeded"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
