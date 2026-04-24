#!/bin/bash
# 3-agent fan-out via send-file: agent-a sends the same 8 KiB file to
# agent-b and agent-c back-to-back; both must receive it with matching
# SHA-256. This tests that a single daemon can keep two independent
# transfer tunnels warm simultaneously without cross-corruption.

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
echo "3-agent fan-out send-file"
echo "=========================================="

log_test "Starting 3-agent stack (clean)"
$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b agent-c >/dev/null 2>&1
if COUNT=$(wait_all_registered 3 rendezvous); then
    log_pass "3 agents registered"
else
    log_fail "registration failed (total=$COUNT)"
    $DC down -v >/dev/null 2>&1
    exit 1
fi

log_test "prep 8KiB source file on agent-a"
$DC exec -T agent-a bash -c 'head -c 8192 /dev/urandom > /tmp/fanout.bin' >/dev/null 2>&1
SRC=$($DC exec -T agent-a sha256sum /tmp/fanout.bin | awk '{print $1}')
if [ -n "$SRC" ]; then
    log_pass "source sha=${SRC:0:12}..."
else
    log_fail "could not make source file"
fi

log_test "send-file a->b and a->c (sequential)"
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-b /tmp/fanout.bin >/tmp/sf_b.txt 2>&1
$DC exec -T agent-a timeout 30 pilotctl --json send-file agent-c /tmp/fanout.bin >/tmp/sf_c.txt 2>&1

check_recv() {
    local who=$1
    local svc="agent-$who"
    local name
    name=$($DC exec -T "$svc" bash -c "ls /root/.pilot/received | grep '^fanout' | head -n1" | tr -d '\r\n')
    if [ -z "$name" ]; then
        echo ""
        return 1
    fi
    $DC exec -T "$svc" sha256sum "/root/.pilot/received/$name" | awk '{print $1}'
}

DST_B=$(check_recv b)
DST_C=$(check_recv c)

log_test "agent-b received copy matches"
if [ "$DST_B" = "$SRC" ] && [ -n "$DST_B" ]; then
    log_pass "b sha match (${DST_B:0:12}...)"
else
    log_fail "b sha mismatch src=${SRC:0:12}... dst=${DST_B:0:12}..."
fi

log_test "agent-c received copy matches"
if [ "$DST_C" = "$SRC" ] && [ -n "$DST_C" ]; then
    log_pass "c sha match (${DST_C:0:12}...)"
else
    log_fail "c sha mismatch src=${SRC:0:12}... dst=${DST_C:0:12}..."
fi

log_test "no panics/fatals in daemon logs"
BAD=$($DC logs agent-a agent-b agent-c 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
if [ -z "$BAD" ]; then
    log_pass "clean logs"
else
    log_fail "$BAD"
fi

$DC down -v >/dev/null 2>&1

echo
echo "=========================================="
echo "Fan-out file summary"
echo "=========================================="
echo -e "Passed: ${GREEN}${PASSED}${NC}"
echo -e "Failed: ${RED}${FAILED}${NC}"
echo "=========================================="

[ "$FAILED" -eq 0 ]
