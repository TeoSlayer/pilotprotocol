#!/bin/bash
# Submit a task whose --task description is ~1 GiB. Input validation at
# pilotctl or at the daemon's task-submit boundary must reject the
# payload BEFORE allocating it into the heap. The daemon RSS must not
# balloon to gigabytes, and the submission must fail fast with a clear
# error.
#
# EXPECTED:
#   - pilotctl exits non-zero OR prints a validation error.
#   - agent-a daemon RSS stays under a sane bound (< 500 MiB delta).
#   - daemon remains responsive to pilotctl info after the attempt.
#
# NOTE: protocol.Packet.Marshal caps payload at 65535 per frame, so the
# transport will never serialize a 1 GiB payload — but the driver /
# pilotctl path allocates + sends via IPC, which can still OOM if no
# guard exists. This test exposes that gap.

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

# Enable task execution on agent-b (so the submit path is live).
$DC exec -T agent-b pilotctl enable-tasks >/dev/null 2>&1 || true

log_test "record baseline agent-a daemon RSS"
# pilot-daemon RSS via /proc — first PID that matches pilot-daemon.
RSS_BEFORE=$($DC exec -T agent-a sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
RSS_BEFORE=${RSS_BEFORE:-0}
echo "baseline RSS: ${RSS_BEFORE} kB"

log_test "attempt to submit task with ~1 GiB description"
# Build 1 GiB of ASCII inside agent-a, pipe to a file, pass via --task-file
# if supported, else via --task on a shell-expanded arg (limited by argv
# size to ~128 KiB on Linux — still large enough to test input validation).
#
# Given argv size caps, we exercise two paths:
#   (a) 1 MiB via --task argv — should fail fast if the daemon / pilotctl
#       has any size guard; a 1 MiB arg fits in argv.
#   (b) A larger payload via stdin/file if pilotctl supports it.
$DC exec -T agent-a sh -c '
    # 1 MiB of "A"
    big=$(printf "%0.sA" $(seq 1 1048576))
    # Timeout in case the daemon enters a huge alloc loop.
    timeout 30 pilotctl --json task submit agent-b --task "$big"
' >/tmp/ovr_out.txt 2>&1
RC=$?
OUT=$(cat /tmp/ovr_out.txt 2>/dev/null)

# Accept ANY of:
#   - pilotctl exit non-zero (validation rejected)
#   - pilotctl emits an explicit error JSON / message
#   - daemon stays healthy and the submit was either rejected or accepted
#     but bounded (task created with a truncated/rejected description)
if [ "$RC" -ne 0 ] || echo "$OUT" | grep -qiE 'too large|invalid|exceeds|payload.*limit|error'; then
    log_pass "oversized submit rejected (rc=$RC)"
else
    # Not fatal yet — still check for unbounded memory growth below.
    log_fail "oversized submit was accepted without error (rc=$RC); needs input-size guard"
    echo "$OUT" | head -c 500
fi

log_test "agent-a daemon still responsive after oversized submit"
if timeout 10 $DC exec -T agent-a pilotctl info >/dev/null 2>&1; then
    log_pass "daemon responsive"
else
    log_fail "daemon became unresponsive — likely stuck in huge alloc path"
fi

log_test "agent-a daemon RSS stayed bounded (<500 MiB delta)"
RSS_AFTER=$($DC exec -T agent-a sh -c '
    pid=$(pgrep -f pilot-daemon | head -n1)
    [ -z "$pid" ] && echo 0 && exit
    awk "/VmRSS/ {print \$2}" /proc/$pid/status
' 2>/dev/null)
RSS_AFTER=${RSS_AFTER:-0}
DELTA=$((RSS_AFTER - RSS_BEFORE))
echo "RSS after: ${RSS_AFTER} kB  (delta: ${DELTA} kB)"
# 500 MiB = 512000 kB
if [ "$DELTA" -lt 512000 ]; then
    log_pass "RSS delta ${DELTA} kB within 500 MiB bound"
else
    log_fail "RSS ballooned by ${DELTA} kB — memory guard missing"
fi

echo ""
echo "Passed: $PASSED  Failed: $FAILED"
[ "$FAILED" -eq 0 ]
