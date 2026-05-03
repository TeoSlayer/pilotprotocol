#!/bin/bash
# Matrix 2 F-series: hot-path key rotation from the CLI.
#
# Tracked by task #146. Today `pilotctl rotate-key <node_id> <email>`
# exists but is a REGISTRY-ONLY rotation — it regenerates the
# registry-signed identity record but does NOT force the tunnel
# layer to re-key in place. No pilotctl command currently drives
# the in-tunnel rekey (maybeRequestRekey / sendKeyExchangeToNode).
#
# This test probes for a hot-path rekey feature. If the CLI exposes
# one (e.g. `pilotctl rekey <peer>` or similar), the test exercises it.
# Otherwise it logs [SKIP] and exits 0.

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
PASSED=0
FAILED=0

ts() { date '+%Y-%m-%d %H:%M:%S'; }
log_test() { echo -e "[$(ts)] ${YELLOW}[TEST]${NC} $*"; }
log_pass() { echo -e "[$(ts)] ${GREEN}[PASS]${NC} $*"; PASSED=$((PASSED+1)); }
log_fail() { echo -e "[$(ts)] ${RED}[FAIL]${NC} $*"; FAILED=$((FAILED+1)); }
log_skip() { echo -e "[$(ts)] ${BLUE}[SKIP]${NC} $*"; }

DC="docker compose -f docker-compose.multi.yml"

cd "$(dirname "$0")" || exit 1

echo "=========================================="
echo "Hot-path key rotation (task #146)"
echo "=========================================="

# Probe: does pilotctl expose a command that drives the in-tunnel
# rekey path? We look for any of: `rekey`, `rotate-tunnel-key`,
# `rotate-session-key`. None of these are currently implemented.
PROBE=$(docker run --rm --entrypoint pilotctl \
    $($DC config --images 2>/dev/null | head -n1) help 2>/dev/null \
    || echo "")

if echo "$PROBE" | grep -Eq '^\s*(rekey|rotate-tunnel-key|rotate-session-key)\b'; then
    # Feature exists, run the real test.
    log_test "hot-path rekey CLI exists; running real test"
    # Placeholder — actual assertions would go here once the feature
    # lands. For now, fail loudly so we notice the feature shipped.
    log_fail "TODO: fill in real assertions once task #146 is merged"
    echo "  pilotctl help surface includes a rekey command — update this test."
    exit 1
fi

# Fallback: also check the running agent if the probe above failed
# (e.g., image not in cache).
$DC up -d rendezvous agent-a agent-b >/dev/null 2>&1
sleep 3
HELP=$($DC exec -T agent-a pilotctl help 2>&1 || true)
if echo "$HELP" | grep -Eq '^\s*(rekey|rotate-tunnel-key|rotate-session-key)\b'; then
    log_test "hot-path rekey CLI exists (agent probe); running real test"
    log_fail "TODO: fill in real assertions once task #146 is merged"
    exit 1
fi

# Also try invoking a hypothetical command to confirm it's absent.
RESP=$($DC exec -T agent-a pilotctl rekey agent-b 2>&1 || true)
if echo "$RESP" | grep -Eqi 'unknown|invalid|unavailable|not[-_ ]?implemented|unrecognized'; then
    log_skip "pilotctl has no hot-path rekey command yet (task #146 pending): $RESP"
    echo "=========================================="
    echo "SKIPPED — feature not yet shipped"
    echo "=========================================="
    $DC down -v >/dev/null 2>&1 || true
    exit 0
fi

# If we got some other response, still treat as skip but note it.
log_skip "rekey probe indeterminate; treating as not-implemented. Raw: $(echo "$RESP" | head -c 200)"
$DC down -v >/dev/null 2>&1 || true
exit 0
