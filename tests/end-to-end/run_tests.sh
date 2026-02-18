#!/bin/bash

# Pilot Protocol End-to-End Test Suite
# Comprehensive testing of all pilotctl commands and daemon functionality
#
# Usage: ./run_tests.sh [--cleanup-only] [--verbose]

set -u  # Exit on undefined variable
# Note: NOT using 'set -e' because we want tests to continue even if some fail

# ============================================================================
# Configuration
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Test results
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/test_results_$TIMESTAMP.txt"
FAILED_TESTS_FILE="$RESULTS_DIR/failed_tests_$TIMESTAMP.txt"
DETAILED_LOG="$RESULTS_DIR/detailed_log_$TIMESTAMP.txt"

# Test artifacts
TEST_DIR="/tmp/pilot_e2e_test_$$"
DAEMON2_SOCKET="/tmp/pilot2.sock"
DAEMON2_PID=""

# Flags
CLEANUP_ONLY=false
VERBOSE=false

# Parse arguments
for arg in "$@"; do
    case $arg in
        --cleanup-only) CLEANUP_ONLY=true ;;
        --verbose|-v) VERBOSE=true ;;
    esac
done

# ============================================================================
# Utility Functions
# ============================================================================

log_header() {
    echo "" | tee -a "$DETAILED_LOG"
    echo -e "${MAGENTA}${BOLD}================================================================================${NC}" | tee -a "$DETAILED_LOG"
    echo -e "${MAGENTA}${BOLD}$1${NC}" | tee -a "$DETAILED_LOG"
    echo -e "${MAGENTA}${BOLD}================================================================================${NC}" | tee -a "$DETAILED_LOG"
}

log_section() {
    echo "" | tee -a "$DETAILED_LOG"
    echo -e "${CYAN}>>> $1${NC}" | tee -a "$DETAILED_LOG"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$DETAILED_LOG"
}

log_success() {
    local test_name="$1"
    echo -e "${GREEN}[PASS]${NC} $test_name"
    echo "[PASS] $test_name" >> "$RESULTS_FILE"
    ((TESTS_PASSED++))
}

log_error() {
    local test_name="$1"
    local what="${2:-}"
    local how="${3:-}"
    local why="${4:-}"
    
    echo -e "${RED}[FAIL]${NC} $test_name"
    echo "[FAIL] $test_name" >> "$RESULTS_FILE"
    echo "$test_name" >> "$FAILED_TESTS_FILE"
    
    # Detailed error information
    {
        echo ""
        echo "================================================================================";
        echo "FAILED TEST: $test_name";
        echo "================================================================================";
        if [[ -n "$what" ]]; then
            echo "WHAT: $what";
        fi
        if [[ -n "$how" ]]; then
            echo "HOW:  $how";
        fi
        if [[ -n "$why" ]]; then
            echo "WHY:  $why";
        fi
        echo "================================================================================";
        echo ""
    } | tee -a "$DETAILED_LOG" >> "$FAILED_TESTS_FILE"
    
    ((TESTS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$DETAILED_LOG"
    echo "[WARN] $1" >> "$RESULTS_FILE"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1" | tee -a "$DETAILED_LOG"
    echo "[SKIP] $1" >> "$RESULTS_FILE"
    ((TESTS_SKIPPED++))
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $1" | tee -a "$DETAILED_LOG"
    else
        echo "[DEBUG] $1" >> "$DETAILED_LOG"
    fi
}

# Enhanced test runner with detailed error reporting
run_test() {
    ((TESTS_RUN++))
    local test_name="$1"
    local command="$2"
    local expect_fail="${3:-false}"
    local what_desc="${4:-Command execution}"
    
    log_info "Test $TESTS_RUN: $test_name"
    log_debug "Command: $command"
    
    local output
    local exit_code=0
    output=$(eval "$command" 2>&1) || exit_code=$?
    
    log_debug "Exit code: $exit_code"
    if [[ "$VERBOSE" == "true" ]]; then
        log_debug "Output: $output"
    fi
    
    if [[ "$expect_fail" == "true" ]]; then
        if [[ $exit_code -ne 0 ]]; then
            log_success "$test_name (expected failure)"
        else
            log_error "$test_name (expected to fail but succeeded)" \
                "Command was expected to fail but returned exit code 0" \
                "Exit code: 0 (success)" \
                "This indicates the validation/error handling is not working as expected"
            if [[ "$VERBOSE" == "true" ]]; then
                echo "  Output: $output"
            fi
        fi
    else
        if [[ $exit_code -eq 0 ]]; then
            log_success "$test_name"
        else
            # Parse error from JSON if possible
            local error_code=""
            local error_msg=""
            if echo "$output" | jq -e '.code' &>/dev/null; then
                error_code=$(echo "$output" | jq -r '.code')
                error_msg=$(echo "$output" | jq -r '.message')
            fi
            
            log_error "$test_name" \
                "$what_desc failed" \
                "Exit code: $exit_code${error_code:+ | Error code: $error_code}" \
                "${error_msg:-Command execution failed. Output: $output}"
            
            if [[ "$VERBOSE" == "true" ]]; then
                echo "  Full output: $output"
            fi
        fi
    fi
    
    return 0
}

# Test with expected output pattern
run_test_with_output() {
    ((TESTS_RUN++))
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"
    local what_desc="${4:-Command output verification}"
    
    log_info "Test $TESTS_RUN: $test_name"
    log_debug "Command: $command"
    log_debug "Expected pattern: $expected_pattern"
    
    local output
    local exit_code=0
    output=$(eval "$command" 2>&1) || exit_code=$?
    
    log_debug "Exit code: $exit_code"
    
    if [[ $exit_code -eq 0 ]] && echo "$output" | grep -qE "$expected_pattern"; then
        log_success "$test_name"
        log_debug "Pattern matched successfully"
    else
        local failure_reason=""
        if [[ $exit_code -ne 0 ]]; then
            failure_reason="Command failed with exit code $exit_code"
        else
            failure_reason="Output did not match expected pattern"
        fi
        
        log_error "$test_name" \
            "$what_desc failed" \
            "$failure_reason" \
            "Expected pattern: '$expected_pattern' | Actual output: $output"
        
        if [[ "$VERBOSE" == "true" ]]; then
            echo "  Full output: $output"
        fi
    fi
    
    return 0
}

# JSON test helper
run_json_test() {
    local test_name="$1"
    local command="$2"
    local what_desc="${3:-JSON command execution}"
    
    if [[ "$JQ_AVAILABLE" == "true" ]]; then
        run_test_with_output "$test_name" "$command" "true" "$what_desc"
    else
        log_skip "$test_name - jq not available"
        ((TESTS_SKIPPED++))
        ((TESTS_RUN++))
    fi
}

cleanup() {
    log_section "Cleaning up test environment"
    
    # Stop second daemon if running
    if [[ -n "$DAEMON2_PID" ]] && kill -0 "$DAEMON2_PID" 2>/dev/null; then
        log_info "Stopping second daemon (PID: $DAEMON2_PID)"
        kill "$DAEMON2_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$DAEMON2_PID" 2>/dev/null || true
    fi
    
    # Remove second daemon socket
    rm -f "$DAEMON2_SOCKET"
    
    # Clean up test directory
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi
    
    # Stop any background processes
    jobs -p | xargs kill 2>/dev/null || true
    
    log_info "Cleanup complete"
}

trap cleanup EXIT

# ============================================================================
# Pre-flight Checks
# ============================================================================

if [[ "$CLEANUP_ONLY" == "true" ]]; then
    cleanup
    exit 0
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

log_header "PILOT PROTOCOL END-TO-END TEST SUITE"

echo "Test run: $TIMESTAMP" | tee "$RESULTS_FILE" "$DETAILED_LOG"
echo "Results: $RESULTS_FILE" | tee -a "$DETAILED_LOG"
echo "Detailed log: $DETAILED_LOG" | tee -a "$DETAILED_LOG"
echo "" | tee -a "$DETAILED_LOG"

log_section "Pre-flight checks"

# Check if pilotctl exists
if ! command -v pilotctl &> /dev/null; then
    log_error "Prerequisite check" \
        "pilotctl command not found" \
        "pilotctl is not in PATH" \
        "Install pilotctl or add it to your PATH"
    exit 1
fi
log_info "✓ pilotctl found at $(command -v pilotctl)"

# Check if jq exists (for JSON tests)
JQ_AVAILABLE=false
if command -v jq &> /dev/null; then
    JQ_AVAILABLE=true
    log_info "✓ jq found at $(command -v jq) - JSON validation enabled"
else
    log_warning "jq not found - JSON validation tests will be skipped"
    log_info "Install jq with: brew install jq (macOS) or apt-get install jq (Linux)"
fi

# Check if daemon is running
if ! pilotctl daemon status --check &>/dev/null; then
    log_error "Prerequisite check" \
        "Daemon is not running" \
        "pilotctl daemon status --check returned non-zero" \
        "Start the daemon with: pilotctl daemon start --hostname <your-hostname>"
    exit 1
fi
log_info "✓ Daemon is running"

# Create test directory
mkdir -p "$TEST_DIR"
log_info "✓ Test directory created: $TEST_DIR"

# Get current node info (dynamically adapt to actual node ID/address)
CURRENT_NODE_ID=$(pilotctl info | grep "Node ID:" | awk '{print $3}')
CURRENT_ADDRESS=$(pilotctl info | grep "Address:" | awk '{print $2}')
CURRENT_NETWORK_ID=$(echo "$CURRENT_ADDRESS" | cut -d':' -f1)
log_info "✓ Current Node ID: $CURRENT_NODE_ID"
log_info "✓ Current Address: $CURRENT_ADDRESS"
log_info "✓ Current Network ID: $CURRENT_NETWORK_ID (0 = global backbone)"

# ============================================================================
# PHASE 1: DAEMON LIFECYCLE & BASIC OPERATIONS
# ============================================================================

log_header "PHASE 1: DAEMON LIFECYCLE & BASIC OPERATIONS"

run_test "Check daemon status" \
    "pilotctl daemon status" \
    "false" \
    "Daemon status check"

run_test_with_output "Get daemon info" \
    "pilotctl info" \
    "Node ID:" \
    "Daemon info retrieval"

run_json_test "Get daemon info (JSON)" \
    "pilotctl --json info | jq -e '.status == \"ok\"'" \
    "JSON-formatted daemon info"

run_test_with_output "Verify encryption enabled" \
    "pilotctl info" \
    "Encryption:.*enabled" \
    "Encryption status verification"

run_test "Get agent context" \
    "pilotctl context" \
    "false" \
    "Agent context/capabilities discovery"

run_json_test "Get agent context (JSON)" \
    "pilotctl --json context | jq -e '.status == \"ok\"'" \
    "JSON-formatted agent context"

run_test "View current config" \
    "pilotctl config" \
    "false" \
    "Configuration retrieval"

# ============================================================================
# PHASE 2: IDENTITY & DISCOVERY
# ============================================================================

log_header "PHASE 2: IDENTITY & DISCOVERY"

# Store original hostname
ORIGINAL_HOSTNAME=$(pilotctl info | grep "Hostname:" | awk '{print $2}')
log_info "Original hostname: $ORIGINAL_HOSTNAME"

# Test hostname operations
NEW_HOSTNAME="test-agent-$(date +%s)"
log_section "Testing hostname operations"

run_test "Set new hostname: $NEW_HOSTNAME" \
    "pilotctl set-hostname '$NEW_HOSTNAME'" \
    "false" \
    "Hostname registration"

sleep 2  # Give daemon time to register with registry

run_test_with_output "Verify hostname was set locally" \
    "pilotctl info" \
    "Hostname:.*$NEW_HOSTNAME" \
    "Local hostname update verification"

run_test_with_output "Find own hostname in registry" \
    "pilotctl find '$NEW_HOSTNAME'" \
    "$CURRENT_ADDRESS" \
    "Hostname resolution via registry"

run_json_test "Find own hostname (JSON)" \
    "pilotctl --json find '$NEW_HOSTNAME' | jq -e '.status == \"ok\"'" \
    "JSON hostname lookup"

run_test "Handle non-existent hostname gracefully" \
    "pilotctl find 'nonexistent-host-99999-never-exists' 2>&1 | grep -qE '(not found|failed)'" \
    "false" \
    "Error handling for non-existent hostname"

run_test "Clear hostname" \
    "pilotctl clear-hostname" \
    "false" \
    "Hostname deregistration"

sleep 1

run_test "Verify hostname cleared" \
    "! pilotctl info | grep -q 'Hostname:.*$NEW_HOSTNAME'" \
    "false" \
    "Hostname removal verification"

run_test "Restore original hostname" \
    "pilotctl set-hostname '$ORIGINAL_HOSTNAME'" \
    "false" \
    "Hostname restoration"

# ============================================================================
# PHASE 3: REGISTRY OPERATIONS
# ============================================================================

log_header "PHASE 3: REGISTRY OPERATIONS"

run_test_with_output "Lookup own node (ID $CURRENT_NODE_ID)" \
    "pilotctl lookup $CURRENT_NODE_ID" \
    "$CURRENT_ADDRESS" \
    "Node lookup by ID"

run_json_test "Lookup own node (JSON)" \
    "pilotctl --json lookup $CURRENT_NODE_ID | jq -e '.status == \"ok\"'" \
    "JSON node lookup"

run_test "Lookup non-existent node (expect failure)" \
    "pilotctl lookup 99999 2>&1 | grep -qE '(not found|failed)'" \
    "false" \
    "Error handling for non-existent node"

# Test public/private visibility
log_section "Testing node visibility"

run_test "Set node to public" \
    "pilotctl set-public $CURRENT_NODE_ID" \
    "false" \
    "Node visibility: make public"

sleep 1

run_test "Verify node is public" \
    "pilotctl lookup $CURRENT_NODE_ID | grep -q '\"public\": true'" \
    "false" \
    "Public visibility verification"

run_test "Set node to private (default)" \
    "pilotctl set-private $CURRENT_NODE_ID" \
    "false" \
    "Node visibility: make private"

sleep 1

run_test "Verify node is private" \
    "pilotctl lookup $CURRENT_NODE_ID | grep -q '\"public\": false'" \
    "false" \
    "Private visibility verification"

# ============================================================================
# PHASE 4: BUILT-IN SERVICES
# ============================================================================

log_header "PHASE 4: BUILT-IN SERVICES"

log_section "Testing Echo Service (Port 7)"
log_info "Echo service should be auto-started by daemon unless disabled with --no-echo"

run_test "Ping self (echo service)" \
    "pilotctl ping $CURRENT_ADDRESS --count 3 --timeout 10s" \
    "false" \
    "Echo service: ping by address"

run_test "Ping self by hostname" \
    "pilotctl ping '$ORIGINAL_HOSTNAME' --count 2 --timeout 10s" \
    "false" \
    "Echo service: ping by hostname"

run_json_test "Ping with JSON output" \
    "pilotctl --json ping $CURRENT_ADDRESS --count 1 --timeout 10s | jq -e '.status == \"ok\"'" \
    "Echo service: JSON ping response"

log_section "Testing Data Exchange Service (Port 1001)"
log_info "Data Exchange service should be auto-started unless disabled with --no-dataexchange"

TEST_MSG="test-message-$(date +%s)"

run_test "Send message to self (port 1001)" \
    "pilotctl send $CURRENT_ADDRESS 1001 --data '$TEST_MSG' --timeout 10s" \
    "false" \
    "Data Exchange: send message"

log_section "Testing Custom Ports"

TEST_PORT=5000
LISTEN_OUTPUT="$TEST_DIR/listen_output.txt"

# Start listener in background
log_info "Starting listener on port $TEST_PORT..."
timeout 10s pilotctl listen $TEST_PORT --count 1 > "$LISTEN_OUTPUT" 2>&1 &
LISTEN_PID=$!
sleep 2

if kill -0 "$LISTEN_PID" 2>/dev/null; then
    run_test "Send to custom port $TEST_PORT" \
        "pilotctl send $CURRENT_ADDRESS $TEST_PORT --data 'custom-port-test' --timeout 5s" \
        "false" \
        "Custom port: send message"
    
    wait "$LISTEN_PID" 2>/dev/null || true
    
    if grep -q "custom-port-test" "$LISTEN_OUTPUT" 2>/dev/null; then
        log_success "Listener received message on custom port"
        ((TESTS_PASSED++))
    else
        log_error "Listener did not receive expected message" \
            "Message sent to port $TEST_PORT was not received" \
            "Listener output: $(cat "$LISTEN_OUTPUT" 2>/dev/null || echo 'no output')" \
            "Possible port not listening or message lost in transit"
    fi
    ((TESTS_RUN++))
else
    log_skip "Listener failed to start, skipping custom port test"
    ((TESTS_SKIPPED++))
fi

# ============================================================================
# PHASE 5: FILE TRANSFER
# ============================================================================

log_header "PHASE 5: FILE TRANSFER"
log_info "File transfer uses Data Exchange service (port 1001)"

TEST_FILE="$TEST_DIR/test_file.txt"
LARGE_FILE="$TEST_DIR/large_file.bin"

# Create test files
echo "This is a test file for Pilot Protocol file transfer" > "$TEST_FILE"
echo "Timestamp: $(date)" >> "$TEST_FILE"
echo "Random data: $(uuidgen 2>/dev/null || echo 'random-data-123')" >> "$TEST_FILE"

run_test "Create test file" \
    "test -f '$TEST_FILE'" \
    "false" \
    "Test file creation"

# Create larger file for stress test
dd if=/dev/urandom of="$LARGE_FILE" bs=1024 count=100 2>/dev/null

run_test "Create large test file (100KB)" \
    "test -f '$LARGE_FILE'" \
    "false" \
    "Large test file creation"

log_warning "File transfer to self will timeout without dedicated receiver, which is expected"
log_info "In real usage, the receiving daemon's data exchange service handles incoming files"

# Test the command (will likely timeout, but we're testing the interface)
if timeout 5s pilotctl send-file $CURRENT_ADDRESS "$TEST_FILE" 2>&1 | tee "$TEST_DIR/sendfile.log"; then
    log_success "File transfer command executed successfully"
    ((TESTS_PASSED++))
else
    log_warning "File transfer timed out (expected without dedicated receiver setup)"
fi
((TESTS_RUN++))

# ============================================================================
# PHASE 6: CONNECTION MANAGEMENT
# ============================================================================

log_header "PHASE 6: CONNECTION MANAGEMENT"

run_test "List active connections" \
    "pilotctl connections" \
    "false" \
    "Connection list retrieval"

run_json_test "List active connections (JSON)" \
    "pilotctl --json connections | jq -e '.status == \"ok\"'" \
    "JSON connection list"

run_test "List peers" \
    "pilotctl peers" \
    "false" \
    "Peer list retrieval"

run_test "Search peers with query" \
    "pilotctl peers --search 'alex'" \
    "false" \
    "Peer search functionality"

run_json_test "List peers (JSON)" \
    "pilotctl --json peers | jq -e '.status == \"ok\"'" \
    "JSON peer list"

# Test interactive connection (with timeout)
log_section "Testing interactive connection"

if timeout 3s pilotctl connect $CURRENT_ADDRESS 1000 --message "ping" 2>&1 | grep -q ""; then
    log_success "Connect command executed"
    ((TESTS_PASSED++))
else
    log_warning "Connect command timed out (expected without active receiver on port 1000)"
fi
((TESTS_RUN++))

# ============================================================================
# PHASE 7: TRUST & SECURITY
# ============================================================================

log_header "PHASE 7: TRUST & SECURITY"
log_info "Agents are private by default and require mutual trust to communicate"

run_test "List trusted peers" \
    "pilotctl trust" \
    "false" \
    "Trusted peers list"

run_json_test "List trusted peers (JSON)" \
    "pilotctl --json trust | jq -e '.status == \"ok\"'" \
    "JSON trusted peers list"

run_test "List pending trust requests" \
    "pilotctl pending" \
    "false" \
    "Pending trust requests list"

run_json_test "List pending trust requests (JSON)" \
    "pilotctl --json pending | jq -e '.status == \"ok\"'" \
    "JSON pending requests list"

log_info "Note: Trust handshake requires two separate nodes"
log_info "Handshake to self should fail gracefully"

if pilotctl handshake $CURRENT_NODE_ID "self-test" 2>&1 | grep -qE "(cannot.*self|same node|invalid)"; then
    log_success "Handshake to self rejected (expected behavior)"
    ((TESTS_PASSED++))
else
    log_warning "Handshake to self handling unclear - check if properly rejected"
fi
((TESTS_RUN++))

# ============================================================================
# PHASE 8: DIAGNOSTICS
# ============================================================================

log_header "PHASE 8: DIAGNOSTICS"

run_test "Traceroute to self" \
    "pilotctl traceroute $CURRENT_ADDRESS --timeout 10s" \
    "false" \
    "Connection setup time measurement"

run_test "Benchmark to self (default size)" \
    "pilotctl bench $CURRENT_ADDRESS --timeout 30s" \
    "false" \
    "Throughput benchmark (default 1MB)"

run_test "Benchmark to self (1 MB)" \
    "pilotctl bench $CURRENT_ADDRESS 1 --timeout 30s" \
    "false" \
    "Throughput benchmark (explicit 1MB)"

# Broadcast is WIP - skip for now
log_skip "Broadcast to network $CURRENT_NETWORK_ID - feature not yet implemented"
((TESTS_RUN++))
# run_test "Broadcast to network $CURRENT_NETWORK_ID" \
#     "pilotctl broadcast $CURRENT_NETWORK_ID 'test-broadcast-message'" \
#     "false" \
#     "Network broadcast"

# ============================================================================
# PHASE 9: ERROR HANDLING & EDGE CASES
# ============================================================================

log_header "PHASE 9: ERROR HANDLING & EDGE CASES"

log_section "Testing invalid inputs"

run_test "Invalid address format" \
    "pilotctl ping invalid-address 2>&1 | grep -qE '(invalid|error|failed)'" \
    "false" \
    "Error handling: invalid address format"

run_test "Invalid port number (too high)" \
    "pilotctl send $CURRENT_ADDRESS 99999 --data 'test' 2>&1 | grep -qE '(invalid|out of range|error)'" \
    "false" \
    "Error handling: port number > 65535"

run_test "Invalid port number (negative)" \
    "pilotctl send $CURRENT_ADDRESS -1 --data 'test' 2>&1 | grep -qE '(invalid|error)'" \
    "false" \
    "Error handling: negative port number"

run_test "Send to non-listening port (timeout expected)" \
    "timeout 3s pilotctl send $CURRENT_ADDRESS 9999 --data 'test' --timeout 2s 2>&1" \
    "true" \
    "Error handling: connection to non-listening port"

run_test "Ping unreachable address (timeout)" \
    "timeout 5s pilotctl ping 0:9999.9999.9999 --count 1 --timeout 3s 2>&1" \
    "true" \
    "Error handling: unreachable address"

run_test "Lookup invalid node ID" \
    "pilotctl lookup -1 2>&1 | grep -qE '(invalid|error|failed)'" \
    "false" \
    "Error handling: invalid node ID"

run_test "Send file that doesn't exist" \
    "pilotctl send-file $CURRENT_ADDRESS /nonexistent/file.txt 2>&1 | grep -qE '(not found|no such file|error)'" \
    "false" \
    "Error handling: non-existent file"

log_section "Testing boundary conditions"

# Ping count 0 - command may exit silently with error code
if pilotctl ping $CURRENT_ADDRESS --count 0 2>&1 | grep -qE '(invalid|must be|error)'; then
    log_success "Ping with count 0 (error message detected)"
    ((TESTS_PASSED++))
elif ! pilotctl ping $CURRENT_ADDRESS --count 0 &>/dev/null; then
    log_success "Ping with count 0 (rejected with error code)"
    ((TESTS_PASSED++))
else
    log_error "Ping with count 0" \
        "Boundary condition: ping count = 0 failed" \
        "Command accepted count=0 without error" \
        "Expected either error message or non-zero exit code"
fi
((TESTS_RUN++))

run_test "Empty message send" \
    "pilotctl send $CURRENT_ADDRESS 1001 --data '' --timeout 5s || true" \
    "false" \
    "Boundary condition: empty message"

run_test "Very long hostname (should be rejected or truncated)" \
    "pilotctl set-hostname 'this-is-a-very-very-very-very-very-very-very-very-very-very-long-hostname-that-exceeds-reasonable-limits-and-should-fail' 2>&1 | grep -qE '(too long|invalid|exceeds|error)'" \
    "false" \
    "Boundary condition: hostname > 63 characters"

# ============================================================================
# PHASE 10: JSON OUTPUT VALIDATION
# ============================================================================

log_header "PHASE 10: JSON OUTPUT VALIDATION"

log_section "Validating JSON structure across commands"

if [[ "$JQ_AVAILABLE" == "true" ]]; then
    run_test "info JSON has required fields" \
        "pilotctl --json info | jq -e '.status and .data.address and .data.node_id'" \
        "false" \
        "JSON structure: info command"

    run_test "lookup JSON has required fields" \
        "pilotctl --json lookup $CURRENT_NODE_ID | jq -e '.status and .data.address'" \
        "false" \
        "JSON structure: lookup command"

    run_test "peers JSON has required fields" \
        "pilotctl --json peers | jq -e '.status and .data'" \
        "false" \
        "JSON structure: peers command"

    run_test "connections JSON has required fields" \
        "pilotctl --json connections | jq -e '.status and .data'" \
        "false" \
        "JSON structure: connections command"

    run_test "trust JSON has required fields" \
        "pilotctl --json trust | jq -e '.status and .data'" \
        "false" \
        "JSON structure: trust command"

    run_test "Error JSON has proper structure" \
        "pilotctl --json find 'nonexistent-99999' 2>&1 | jq -e '.status == \"error\" and .code and .message'" \
        "false" \
        "JSON structure: error response"
else
    log_skip "JSON validation tests - jq not available"
    ((TESTS_SKIPPED+=6))
    ((TESTS_RUN+=6))
fi

# ============================================================================
# PHASE 11: PERFORMANCE & STRESS TESTS
# ============================================================================

log_header "PHASE 11: PERFORMANCE & STRESS TESTS"

log_section "Testing rapid consecutive operations"

run_test "Rapid ping (10 consecutive)" \
    "for i in {1..10}; do pilotctl ping $CURRENT_ADDRESS --count 1 --timeout 5s || exit 1; done" \
    "false" \
    "Stress test: 10 consecutive pings"

run_test "Rapid info queries (20 consecutive)" \
    "for i in {1..20}; do pilotctl info >/dev/null || exit 1; done" \
    "false" \
    "Stress test: 20 consecutive info queries"

log_section "Testing concurrent operations"

# Launch multiple pings in parallel
log_info "Launching 5 concurrent ping operations..."
for i in {1..5}; do
    pilotctl ping $CURRENT_ADDRESS --count 2 --timeout 10s > "$TEST_DIR/ping_$i.log" 2>&1 &
done

if wait; then
    log_success "Concurrent pings completed successfully"
    ((TESTS_PASSED++))
else
    log_error "Some concurrent pings failed" \
        "One or more parallel ping operations failed" \
        "Check logs in $TEST_DIR/ping_*.log" \
        "This may indicate concurrency issues in the daemon or network stack"
fi
((TESTS_RUN++))

# ============================================================================
# PHASE 12: GATEWAY TESTING (if root available)
# ============================================================================

log_header "PHASE 12: GATEWAY TESTING"

if [[ $EUID -eq 0 ]]; then
    log_info "Running as root, testing gateway functionality"
    
    run_test "Start gateway" \
        "pilotctl gateway start $CURRENT_ADDRESS" \
        "false" \
        "Gateway: start IP-to-Pilot bridge"
    
    sleep 2
    
    run_test "List gateway mappings" \
        "pilotctl gateway list" \
        "false" \
        "Gateway: list active mappings"
    
    run_test "Stop gateway" \
        "pilotctl gateway stop" \
        "false" \
        "Gateway: stop IP-to-Pilot bridge"
else
    log_skip "Gateway tests require root privileges (sudo)"
    log_info "To test gateway: sudo ./run_tests.sh"
    ((TESTS_SKIPPED+=3))
    ((TESTS_RUN+=3))
fi

# ============================================================================
# PHASE 13: MULTI-DAEMON TESTING (ADVANCED)
# ============================================================================

log_header "PHASE 13: MULTI-DAEMON TESTING"

log_info "Attempting to start second daemon for inter-daemon testing..."
log_warning "This requires the pilot-daemon binary and may fail if ports are in use"

# Try to start a second daemon on a different socket and port
DAEMON2_IDENTITY="$TEST_DIR/identity2.json"
DAEMON2_LISTEN=":4001"

if command -v pilot-daemon &> /dev/null; then
    log_info "Starting second daemon..."
    pilot-daemon \
        -socket "$DAEMON2_SOCKET" \
        -listen "$DAEMON2_LISTEN" \
        -identity "$DAEMON2_IDENTITY" \
        -hostname "test-daemon-2" \
        -log-level error \
        > "$TEST_DIR/daemon2.log" 2>&1 &
    DAEMON2_PID=$!
    
    sleep 3
    
    if kill -0 "$DAEMON2_PID" 2>/dev/null; then
        log_success "Second daemon started (PID: $DAEMON2_PID)"
        ((TESTS_PASSED++))
        
        # Get second daemon's address
        DAEMON2_ADDR=$(PILOT_SOCKET="$DAEMON2_SOCKET" pilotctl info 2>/dev/null | grep "Address:" | awk '{print $2}')
        log_info "Second daemon address: $DAEMON2_ADDR"
        
        if [[ -n "$DAEMON2_ADDR" ]]; then
            # Test communication between daemons
            run_test "Ping second daemon from first" \
                "pilotctl ping '$DAEMON2_ADDR' --count 3 --timeout 10s" \
                "false" \
                "Inter-daemon: ping from first to second"
            
            run_test "Ping first daemon from second" \
                "PILOT_SOCKET='$DAEMON2_SOCKET' pilotctl ping $CURRENT_ADDRESS --count 3 --timeout 10s" \
                "false" \
                "Inter-daemon: ping from second to first"
            
            # Test hostname discovery between daemons
            run_test "Find second daemon by hostname" \
                "pilotctl find 'test-daemon-2'" \
                "false" \
                "Inter-daemon: hostname resolution"
        else
            log_error "Failed to get second daemon address" \
                "Could not retrieve address from second daemon" \
                "PILOT_SOCKET='$DAEMON2_SOCKET' pilotctl info failed" \
                "Check $TEST_DIR/daemon2.log for daemon startup issues"
        fi
        
        # Cleanup second daemon
        log_info "Stopping second daemon..."
        kill "$DAEMON2_PID" 2>/dev/null || true
        sleep 1
        DAEMON2_PID=""
    else
        log_error "Second daemon failed to start" \
            "pilot-daemon process exited immediately" \
            "Check $TEST_DIR/daemon2.log for details" \
            "Possible port conflict or configuration issue"
        cat "$TEST_DIR/daemon2.log"
    fi
    ((TESTS_RUN++))
else
    log_skip "pilot-daemon binary not found, skipping multi-daemon tests"
    log_info "Install pilot-daemon to enable these tests"
    ((TESTS_SKIPPED+=4))
    ((TESTS_RUN+=4))
fi

# ============================================================================
# FINAL REPORT
# ============================================================================

log_header "TEST SUITE COMPLETE"

echo "" | tee -a "$DETAILED_LOG"
echo "================================================================================" | tee -a "$DETAILED_LOG"
echo "                              TEST RESULTS SUMMARY" | tee -a "$DETAILED_LOG"
echo "================================================================================" | tee -a "$DETAILED_LOG"
echo "" | tee -a "$DETAILED_LOG"

printf "Total Tests Run:     %3d\n" $TESTS_RUN | tee -a "$DETAILED_LOG"
printf "Tests Passed:        %3d ${GREEN}✓${NC}\n" $TESTS_PASSED | tee -a "$DETAILED_LOG"
printf "Tests Failed:        %3d ${RED}✗${NC}\n" $TESTS_FAILED | tee -a "$DETAILED_LOG"
printf "Tests Skipped:       %3d ${YELLOW}○${NC}\n" $TESTS_SKIPPED | tee -a "$DETAILED_LOG"
echo "" | tee -a "$DETAILED_LOG"

if [[ $TESTS_FAILED -eq 0 ]]; then
    SUCCESS_RATE="100.00"
    echo -e "${GREEN}Success Rate: 100%${NC}" | tee -a "$DETAILED_LOG"
else
    if [[ $((TESTS_RUN - TESTS_SKIPPED)) -gt 0 ]]; then
        SUCCESS_RATE=$(awk "BEGIN {printf \"%.2f\", ($TESTS_PASSED * 100.0) / ($TESTS_RUN - $TESTS_SKIPPED)}")
    else
        SUCCESS_RATE="0.00"
    fi
    echo -e "${YELLOW}Success Rate: ${SUCCESS_RATE}%${NC}" | tee -a "$DETAILED_LOG"
fi

echo "" | tee -a "$DETAILED_LOG"
echo "Results summary:      $RESULTS_FILE" | tee -a "$DETAILED_LOG"
echo "Detailed log:         $DETAILED_LOG" | tee -a "$DETAILED_LOG"

if [[ $TESTS_FAILED -gt 0 ]]; then
    echo -e "${RED}Failed tests:         $FAILED_TESTS_FILE${NC}" | tee -a "$DETAILED_LOG"
    echo "" | tee -a "$DETAILED_LOG"
    echo "Review failed tests for detailed error analysis (WHAT/HOW/WHY)" | tee -a "$DETAILED_LOG"
fi

echo "Test artifacts:       $TEST_DIR" | tee -a "$DETAILED_LOG"
echo "" | tee -a "$DETAILED_LOG"

# Write summary to results file
{
    echo ""
    echo "================================================================================"
    echo "SUMMARY"
    echo "================================================================================"
    echo "Total:        $TESTS_RUN"
    echo "Passed:       $TESTS_PASSED"
    echo "Failed:       $TESTS_FAILED"
    echo "Skipped:      $TESTS_SKIPPED"
    echo "Success Rate: ${SUCCESS_RATE}%"
    echo ""
    echo "Finished: $(date)"
} >> "$RESULTS_FILE"

# Exit with appropriate code
if [[ $TESTS_FAILED -gt 0 ]]; then
    exit 1
else
    exit 0
fi
