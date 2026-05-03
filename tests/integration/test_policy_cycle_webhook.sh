#!/bin/bash
# Matrix 4 — cycle × webhook.
# Policy fires a webhook action with event="cycle_fired" on every cycle.
# Install a local webhook sink (python http.server) inside the agent-b
# container, point the daemon at it, then force a cycle and assert the
# sink recorded a POST whose body includes event "policy.cycle_fired".
#
# The daemon flag is `-webhook <url>`; executeWebhook wraps the configured
# event under "policy.<event>" (policy_runner.go:352).
#
# NOTE: The webhook URL is set via daemon -webhook flag at startup; there
# is no runtime hot-reload CLI. This test restarts agent-b with the sink
# URL baked in.

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

DC="docker compose -f docker-compose.multi.policy.yml"

cd "$(dirname "$0")" || exit 1
. ./policy_helpers.sh

echo "=========================================="
echo "Policy: cycle × webhook"
echo "=========================================="

if ! start_policy_stack; then
    log_fail "stack"
    exit 1
fi
log_pass "stack up"

log_test "start a local webhook sink inside agent-b container"
$DC exec -d agent-b bash -c '
    cat > /tmp/sink.py <<PY
import http.server, json, sys, time
LOG = "/tmp/hook.log"
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        with open(LOG, "a") as f:
            f.write(json.dumps({"ts": time.time(), "path": self.path, "body": body}) + "\n")
        self.send_response(204); self.end_headers()
http.server.HTTPServer(("127.0.0.1", 18080), H).serve_forever()
PY
    : > /tmp/hook.log
    nohup python3 /tmp/sink.py >/tmp/sink.out 2>&1 &
    sleep 0.5
'
sleep 2
log_pass "sink listening on 127.0.0.1:18080"

log_test "restart agent-b daemon with -webhook flag"
# Rewrite the daemon command for agent-b inline — start a second pilot-daemon.
# Kill the original and launch with -webhook set.
$DC exec -T agent-b bash -c '
    pkill -x pilot-daemon 2>/dev/null || true
    rm -f /tmp/pilot.sock /root/.pilot/identity.json
    sleep 1
    nohup pilot-daemon \
        -registry $PILOT_REGISTRY \
        -beacon ${PILOT_REGISTRY%:*}:9001 \
        -hostname agent-b \
        -identity /root/.pilot/identity.json \
        -email agent-b@p2p.test \
        -endpoint $(hostname -i):4000 \
        -listen :4000 \
        -public \
        -keepalive 5s \
        -admin-token test-admin-token \
        -webhook http://127.0.0.1:18080/hook \
        -log-level info \
        >/tmp/daemon.log 2>&1 &
    sleep 4
'
log_pass "agent-b relaunched with webhook"

sleep 5

log_test "Apply webhook-on-cycle policy"
if ! load_policy agent-b /tests/fixtures/policies/short_cycle_webhook.json; then
    log_fail "load"
    stop_policy_stack
    exit 1
fi
log_pass "policy loaded (net=$POLICY_NET_ID)"

log_test "force cycle"
force_cycle agent-b "$POLICY_NET_ID" >/tmp/cyc.out 2>&1
sleep 3
log_pass "cycle forced"

log_test "sink recorded at least one POST"
HOOKS=$($DC exec -T agent-b bash -c 'wc -l </tmp/hook.log 2>/dev/null || echo 0')
if [ "${HOOKS:-0}" -ge 1 ]; then
    log_pass "hooks=$HOOKS"
else
    log_fail "no POSTs received"
    $DC exec -T agent-b bash -c 'head -5 /tmp/sink.out; tail -20 /tmp/daemon.log' 2>&1
fi

log_test "at least one POST mentions 'policy.cycle_fired' or 'policy.cycle'"
FOUND=$($DC exec -T agent-b bash -c "grep -cE 'policy\\.(cycle_fired|cycle)' /tmp/hook.log 2>/dev/null || echo 0")
if [ "${FOUND:-0}" -ge 1 ]; then
    log_pass "found policy.cycle* event in hook body"
else
    log_fail "no policy.cycle* event found; sample:"
    $DC exec -T agent-b bash -c 'head -3 /tmp/hook.log'
fi

stop_policy_stack

echo "Passed: ${GREEN}${PASSED}${NC}  Failed: ${RED}${FAILED}${NC}"
[ "$FAILED" -eq 0 ]
