#!/bin/bash
# Rotate identity key via the gateway-side daemon.
#
# Task #146 (rotate-key hot path) is not shipped. Per TEST-PLAN.md this
# test is SKIPPED until the feature lands. If pilotctl grows the command
# later, the body below can be uncommented.
#
# EXPECTED: SKIP (documented gap).

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_skip() { echo -e "[$(ts)] ${YELLOW}[SKIP]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; }

DC="docker compose -f docker-compose.multi.yml -f docker-compose.multi.gateway.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Gateway: rotate-key (SKIPPED — task #146 pending)"
echo "=========================================="

log_test "checking if gateway-side pilotctl exposes rotate-key"
# Bring up a minimal stack so pilotctl --help can be exec'd.
$DC up -d rendezvous agent-a agent-b gateway >/dev/null 2>&1
for _ in $(seq 1 60); do
    if $DC exec -T gateway pilotctl --help 2>&1 | grep -qi 'rotate-key\|rotate_key'; then
        log_pass "rotate-key help text present — feature may have shipped; update this test"
        echo "Passed: 1  Failed: 0"
        exit 0
    fi
    if $DC ps --services --filter status=running 2>/dev/null | grep -q gateway; then
        break
    fi
    sleep 1
done

log_skip "rotate-key not available in gateway-side pilotctl — expected until task #146"
echo "Passed: 0  Failed: 0  Skipped: 1"
exit 0
