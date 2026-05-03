#!/bin/bash
# Duration: policy with "cycle":"5s" runs for 60s, ≥ 10 cycle-tick events observed.
#
# Builds a minimal test policy config with a 5 s cycle, mounts it into
# agent-a, confirms daemon loads it, runs 60 s, then greps log for at
# least 10 cycle-tick log lines.
# DURATION: 90s

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
RUN=60

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Duration: short-cycle policy 5s x 60s"
echo "=========================================="

$DC down -v >/dev/null 2>&1
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
for _ in $(seq 1 60); do
    COUNT=$($DC exec -T rendezvous curl -fsS http://127.0.0.1:8080/api/stats 2>/dev/null | jq -r '.total_nodes // 0')
    [ "$COUNT" -ge 2 ] && break
    sleep 1
done
[ "$COUNT" -ge 2 ] && log_pass "both agents registered" || { log_fail "agents not up"; exit 1; }

log_test "write short-cycle test policy onto agent-a"
$DC exec -T agent-a bash -c 'cat >/tmp/shortcycle.json <<JSON
{
  "name": "shortcycle-test",
  "network_id": 99,
  "cycle": "5s",
  "rules": [
    {"event": "cycle", "action": "log", "tag": "CYCLE_TICK_TEST"}
  ]
}
JSON'
log_pass "policy written"

log_test "create network with short-cycle rules"
# Real CLI: there is no `policy load` / `network apply`. Networks are
# created with `network create --rules-file`, and policy can be set on
# an existing network via `policy set --net <id> --file <path>`.
OUT=$($DC exec -T agent-a bash -c 'pilotctl --json network create --name shortcycle-test --join-rule open --rules-file /tmp/shortcycle.json 2>&1' 2>&1)
NID=$(echo "$OUT" | jq -r '.data.network_id // .data.id // empty')
if [ -n "$NID" ] && [ "$NID" != "null" ]; then
    log_pass "network created (nid=$NID)"
else
    log_fail "could not create network: $(echo "$OUT" | head -c 200)"
fi

log_test "run ${RUN}s and count cycle events"
START_LINES=$($DC logs agent-a 2>&1 | grep -cE "CYCLE_TICK_TEST|cycle.*tick|policy.*cycle" | tr -d ' \r\n')
START_LINES=${START_LINES:-0}
sleep $RUN
END_LINES=$($DC logs agent-a 2>&1 | grep -cE "CYCLE_TICK_TEST|cycle.*tick|policy.*cycle" | tr -d ' \r\n')
END_LINES=${END_LINES:-0}
DELTA=$((END_LINES - START_LINES))
echo "    cycle tick delta over ${RUN}s: $DELTA (expect >= 10)"
if [ "$DELTA" -ge 10 ]; then
    log_pass "observed $DELTA cycle ticks"
else
    log_fail "only $DELTA cycle ticks (expected >=10 for 5s cycle over ${RUN}s)"
fi

log_test "no panics"
BAD=$($DC logs agent-a agent-b 2>&1 | grep -iE "panic|fatal|race detected" | head -3)
[ -z "$BAD" ] && log_pass "clean logs" || log_fail "found: $BAD"

echo
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
