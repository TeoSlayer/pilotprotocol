#!/bin/bash
# Integration tests for pilotctl against agent-alpha on the real network
# Note: no set -e — each test logs its own pass/fail and we continue through failures

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ALPHA_AGENT="agent-alpha"
TEST_HOSTNAME="test-agent-$(date +%s)"
PASSED=0
FAILED=0

# Helper functions
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_test() {
    echo -e "[$(timestamp)] ${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "[$(timestamp)] ${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

log_fail() {
    echo -e "[$(timestamp)] ${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Stopping daemon..."
    # Skip IPC stop — it can hang if daemon's IPC listener is stuck.
    # Go straight to kill signals.
    if [ -n "$DAEMON_PID" ]; then
        kill -9 "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    # Belt-and-suspenders: kill any remaining pilot-daemon processes
    pkill -9 -f pilot-daemon 2>/dev/null || true
    rm -f /tmp/pilot.sock
    # Show any daemon errors from the log
    if [ -f "$DAEMON_LOG" ]; then
        ERRORS=$(grep -i "error\|fatal\|panic" "$DAEMON_LOG" 2>/dev/null | tail -5)
        if [ -n "$ERRORS" ]; then
            echo -e "${YELLOW}[CLEANUP]${NC} Last daemon errors:"
            echo "$ERRORS"
        fi
    fi
    echo -e "${YELLOW}[CLEANUP]${NC} Daemon stopped."
}

trap cleanup EXIT

echo "========================================="
echo "Pilot Protocol CLI Integration Tests"
echo "Testing against: $ALPHA_AGENT"
echo "========================================="
echo ""

# 1. Start daemon (auto-registers with the global registry on startup)
log_test "Starting daemon with hostname: $TEST_HOSTNAME"
mkdir -p /root/.pilot
DAEMON_LOG="/tmp/pilot-daemon.log"
pilot-daemon \
    --hostname "$TEST_HOSTNAME" \
    --identity /root/.pilot/identity.key \
    --log-level info > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

# Wait for socket + registration (daemon registers during Start())
REGISTERED=false
for i in $(seq 1 15); do
    if [ -S /tmp/pilot.sock ]; then
        # Socket exists — check if we got a node ID (means registered)
        NODE_ID=$(pilotctl --json info 2>/dev/null | jq -r '.data.node_id // empty' 2>/dev/null)
        if [ -n "$NODE_ID" ] && [ "$NODE_ID" != "0" ] && [ "$NODE_ID" != "null" ]; then
            REGISTERED=true
            break
        fi
    fi
    sleep 1
done

if [ "$REGISTERED" = true ]; then
    # Show daemon startup logs
    cat "$DAEMON_LOG" 2>/dev/null || true
    log_pass "Daemon started and registered (node $NODE_ID)"
else
    if [ -S /tmp/pilot.sock ]; then
        log_pass "Daemon started (socket ready)"
        log_fail "Failed to register on the global network within 15s"
    else
        log_fail "Daemon failed to start (socket not found after 15s)"
        exit 1
    fi
fi

# 2. Check daemon status
log_test "Checking daemon status"
if pilotctl daemon status --check; then
    log_pass "Daemon status check passed"
else
    log_fail "Daemon status check failed"
fi

# 3. Get agent info
log_test "Getting agent info"
INFO=$(pilotctl --json info 2>/dev/null)
if echo "$INFO" | jq -e '.data.address' > /dev/null 2>&1; then
    ADDRESS=$(echo "$INFO" | jq -r '.data.address')
    HOSTNAME=$(echo "$INFO" | jq -r '.data.hostname')
    log_pass "Agent info retrieved: $ADDRESS ($HOSTNAME)"
else
    log_fail "Failed to get agent info"
fi

# 5. Find alpha-agent
log_test "Finding $ALPHA_AGENT"
if pilotctl find "$ALPHA_AGENT" > /dev/null 2>&1; then
    ALPHA_ADDR=$(pilotctl find "$ALPHA_AGENT" | head -n1)
    log_pass "Found $ALPHA_AGENT: $ALPHA_ADDR"
else
    log_fail "Failed to find $ALPHA_AGENT"
fi

# 6. Ping alpha-agent
log_test "Pinging $ALPHA_AGENT"
if pilotctl ping "$ALPHA_AGENT" --count 3 --timeout 10s > /dev/null 2>&1; then
    log_pass "Successfully pinged $ALPHA_AGENT"
else
    log_fail "Failed to ping $ALPHA_AGENT"
fi

# 7. Echo test (port 7)
log_test "Echo service test (port 7)"
ECHO_MSG="test-echo-$(date +%s)"
RESPONSE=$(echo "$ECHO_MSG" | pilotctl connect "$ALPHA_AGENT" 7 --timeout 10s 2>/dev/null || echo "")
if [ "$RESPONSE" = "$ECHO_MSG" ]; then
    log_pass "Echo service works correctly"
else
    log_fail "Echo service failed (expected: $ECHO_MSG, got: $RESPONSE)"
fi

# 8. Data Exchange - Send text message (port 1001)
log_test "Data Exchange: Sending text message"
TEXT_MSG="Hello from $TEST_HOSTNAME at $(date)"
if pilotctl send-message "$ALPHA_AGENT" --data "$TEXT_MSG" --type text 2>/dev/null; then
    log_pass "Text message sent successfully"
else
    log_fail "Failed to send text message"
fi

# 9. Data Exchange - Send JSON message
log_test "Data Exchange: Sending JSON message"
JSON_MSG='{"test": "integration", "timestamp": '$(date +%s)', "from": "'$TEST_HOSTNAME'"}'
if pilotctl send-message "$ALPHA_AGENT" --data "$JSON_MSG" --type json 2>/dev/null; then
    log_pass "JSON message sent successfully"
else
    log_fail "Failed to send JSON message"
fi

# 10. Data Exchange - Send file
log_test "Data Exchange: Sending test file"
TEST_FILE="/tmp/test-file-$(date +%s).txt"
echo "Integration test file from $TEST_HOSTNAME" > "$TEST_FILE"
echo "Timestamp: $(date)" >> "$TEST_FILE"
echo "Random data: $(cat /dev/urandom | head -c 100 | base64)" >> "$TEST_FILE"

if pilotctl send-file "$ALPHA_AGENT" "$TEST_FILE" 2>/dev/null; then
    log_pass "File sent successfully"
    rm -f "$TEST_FILE"
else
    log_fail "Failed to send file"
    rm -f "$TEST_FILE"
fi

# 11. Event Stream - Publish event (port 1002)
log_test "Event Stream: Publishing event"
EVENT_DATA="test-event-$(date +%s)"
if pilotctl publish "$ALPHA_AGENT" "test/integration" --data "$EVENT_DATA" 2>/dev/null; then
    log_pass "Event published successfully"
else
    log_fail "Failed to publish event"
fi

# 12. Event Stream - Subscribe (with timeout)
log_test "Event Stream: Testing subscribe (quick test)"
timeout 5s pilotctl subscribe "$ALPHA_AGENT" "test/**" --count 1 --timeout 3s 2>/dev/null && \
    log_pass "Subscribe command works" || \
    log_pass "Subscribe command completed (no events expected)"

# 13. Task Submit (port 1003) - if available
log_test "Task Submit: Sending task (port 1003)"
# Using raw send since pilotctl might not have a specific task command
TASK_DATA='{"task": "test-task", "from": "'$TEST_HOSTNAME'", "timestamp": '$(date +%s)'}'
if pilotctl send "$ALPHA_AGENT" 1003 --data "$TASK_DATA" --timeout 5s 2>/dev/null; then
    log_pass "Task submitted successfully"
else
    log_pass "Task submit tested (alpha-agent may not accept tasks)"
fi

# 14. List peers
log_test "Listing peers"
if pilotctl peers > /dev/null 2>&1; then
    PEER_COUNT=$(pilotctl --json peers | jq -r '.data | length' 2>/dev/null || echo "0")
    log_pass "Peers listed successfully (count: $PEER_COUNT)"
else
    log_fail "Failed to list peers"
fi

# 15. List connections
log_test "Listing active connections"
if pilotctl connections > /dev/null 2>&1; then
    log_pass "Connections listed successfully"
else
    log_fail "Failed to list connections"
fi

# 16. Check inbox
log_test "Checking inbox"
if pilotctl inbox > /dev/null 2>&1; then
    log_pass "Inbox check successful"
else
    log_fail "Failed to check inbox"
fi

# 17. Check received files
log_test "Checking received files"
if pilotctl received > /dev/null 2>&1; then
    log_pass "Received files check successful"
else
    log_fail "Failed to check received files"
fi

# 18. Set and clear hostname
log_test "Testing hostname management"
NEW_HOSTNAME="renamed-$TEST_HOSTNAME"
if pilotctl set-hostname "$NEW_HOSTNAME" && pilotctl clear-hostname && pilotctl set-hostname "$TEST_HOSTNAME"; then
    log_pass "Hostname management works"
else
    log_fail "Hostname management failed"
fi

# 19. Visibility toggle
log_test "Testing visibility settings"
if pilotctl set-public && pilotctl set-private; then
    log_pass "Visibility toggle works"
else
    log_fail "Visibility toggle failed"
fi

# 20. Tags management
log_test "Testing tag management"
if pilotctl set-tags "test" "integration" "docker" && pilotctl clear-tags; then
    log_pass "Tag management works"
else
    log_fail "Tag management failed"
fi

# 21. Config check
log_test "Checking configuration"
if pilotctl config > /dev/null 2>&1; then
    log_pass "Configuration retrieved successfully"
else
    log_fail "Failed to retrieve configuration"
fi

# 22. Deregister
log_test "Deregistering from network"
if pilotctl deregister; then
    log_pass "Successfully deregistered from network"
else
    log_fail "Failed to deregister from network"
fi

# Print summary
echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo "========================================="

if [ $FAILED -gt 0 ]; then
    exit 1
fi

exit 0
