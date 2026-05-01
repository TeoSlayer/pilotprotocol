#!/bin/bash
# Admin-token-gated broadcast across 3 daemons.
#
# Verifies:
#   1. backbone broadcast (network 0) with valid admin token reaches every peer
#   2. broadcast without admin token is rejected
#   3. broadcast with wrong admin token is rejected
#   4. broadcast on a non-zero network with valid token reaches members
#
# Stack: docker-compose.multi3.yml + PILOT_ADMIN_TOKEN env var. The compose
# file substitutes the token into rendezvous + every agent at parse time so
# the daemons are configured to honor it.

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

export PILOT_ADMIN_TOKEN="bcast-secret"
DC="docker compose -f docker-compose.multi3.yml"

cd "$(dirname "$0")" || exit 1
source ./topology_helpers.sh

cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "=========================================="
echo "Broadcast (admin-token gated)"
echo "=========================================="

log_test "starting 3-agent stack with admin token"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "all 3 agents registered (total_nodes=$COUNT)"
else
    log_fail "agents did not register (total=$COUNT)"
    exit 1
fi

# Cache node IDs (network create wants --node-id)
NODE_A=$($DC exec -T agent-a pilotctl --json info | jq -r '.data.node_id // empty')
NODE_B=$($DC exec -T agent-b pilotctl --json info | jq -r '.data.node_id // empty')
NODE_C=$($DC exec -T agent-c pilotctl --json info | jq -r '.data.node_id // empty')
if [ -z "$NODE_A" ] || [ -z "$NODE_B" ] || [ -z "$NODE_C" ]; then
    log_fail "could not read node IDs (a=$NODE_A b=$NODE_B c=$NODE_C)"
    exit 1
fi

# Helpers — start each listener as a host-side backgrounded subshell so its
# stdout flows back through docker exec to a host /tmp file. `docker exec -d`
# does not do this (it discards the channel), so we must keep the foreground
# attachment.
LISTENER_PIDS=""
start_listener() {
    local container="$1" port="$2" tag="$3"
    ( $DC exec -T "$container" pilotctl --json listen "$port" --count 1 --timeout 12s \
        > "/tmp/bcast-${tag}.out" 2>&1 ) &
    LISTENER_PIDS="$LISTENER_PIDS $!"
}

await_listeners() {
    for pid in $LISTENER_PIDS; do wait "$pid" 2>/dev/null; done
    LISTENER_PIDS=""
}

read_listener() {
    local tag="$1"
    jq -r '.data.messages[0].data // empty' < "/tmp/bcast-${tag}.out" 2>/dev/null
}

# ----- 1. Backbone broadcast WITH valid token -----
log_test "backbone (net 0): broadcast with valid token delivers to b and c"
start_listener agent-b 5000 b1
start_listener agent-c 5000 c1
sleep 1

OUT=$($DC exec -T -e PILOT_ADMIN_TOKEN="$PILOT_ADMIN_TOKEN" agent-a \
    pilotctl broadcast 0 "hello-backbone" --port 5000 2>&1)
RC=$?
await_listeners
if [ "$RC" -ne 0 ]; then
    log_fail "backbone broadcast with valid token failed: $OUT"
else
    GOT_B=$(read_listener b1)
    GOT_C=$(read_listener c1)
    if [ "$GOT_B" = "hello-backbone" ] && [ "$GOT_C" = "hello-backbone" ]; then
        log_pass "both b and c received backbone broadcast"
    else
        log_fail "missing receivers (b='$GOT_B' c='$GOT_C')"
    fi
fi

# ----- 2. Broadcast WITHOUT admin token (caller token empty) -----
log_test "broadcast without admin token is rejected"
ERR=$($DC exec -T -e PILOT_ADMIN_TOKEN="" agent-a \
    pilotctl broadcast 0 "no-token" --port 5000 2>&1)
RC=$?
if [ "$RC" -eq 0 ]; then
    log_fail "broadcast without token unexpectedly succeeded: $ERR"
elif echo "$ERR" | grep -qiE "admin token required|broadcast denied"; then
    log_pass "rejected with admin-token-required error"
else
    log_fail "rejected but with unexpected message: $(echo "$ERR" | head -c 160)"
fi

# ----- 3. Broadcast WITH WRONG admin token -----
log_test "broadcast with wrong admin token is rejected"
ERR=$($DC exec -T -e PILOT_ADMIN_TOKEN="this-is-wrong" agent-a \
    pilotctl broadcast 0 "wrong-token" --port 5000 2>&1)
RC=$?
if [ "$RC" -eq 0 ]; then
    log_fail "broadcast with wrong token unexpectedly succeeded: $ERR"
elif echo "$ERR" | grep -qiE "invalid admin token|broadcast denied"; then
    log_pass "rejected with token-mismatch error"
else
    log_fail "rejected but with unexpected message: $(echo "$ERR" | head -c 160)"
fi

# ----- 4. Non-zero network broadcast with valid token -----
log_test "non-zero network: create + join all 3 + broadcast"
NETID=$($DC exec -T -e PILOT_ADMIN_TOKEN="$PILOT_ADMIN_TOKEN" agent-a \
    pilotctl --json network create --name bcast-net --join-rule open --node-id "$NODE_A" 2>&1 \
    | jq -r '.data.network_id // empty')
if [ -z "$NETID" ]; then
    log_fail "network create returned no id"
else
    log_pass "network $NETID created"
    # Self-join via the local daemon (no admin token needed for open networks).
    $DC exec -T agent-b pilotctl network join "$NETID" >/dev/null 2>&1
    $DC exec -T agent-c pilotctl network join "$NETID" >/dev/null 2>&1
    sleep 2

    start_listener agent-b 5000 b2
    start_listener agent-c 5000 c2
    sleep 1

    OUT=$($DC exec -T -e PILOT_ADMIN_TOKEN="$PILOT_ADMIN_TOKEN" agent-a \
        pilotctl broadcast "$NETID" "hello-net" --port 5000 2>&1)
    RC=$?
    await_listeners
    if [ "$RC" -ne 0 ]; then
        log_fail "non-zero net broadcast failed: $OUT"
    else
        GOT_B=$(read_listener b2)
        GOT_C=$(read_listener c2)
        if [ "$GOT_B" = "hello-net" ] && [ "$GOT_C" = "hello-net" ]; then
            log_pass "both b and c received non-zero net broadcast"
        else
            log_fail "missing receivers (b='$GOT_B' c='$GOT_C')"
        fi
    fi
fi

# ----- 5. No panic/fatal in logs -----
log_test "no panic/fatal in agent logs"
BAD=$($DC logs agent-a agent-b agent-c rendezvous 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "found: $BAD"
fi

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
