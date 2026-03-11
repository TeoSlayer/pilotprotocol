# Integration Testing

Docker-based integration tests that validate the entire stack against the real Pilot Protocol network.

## Overview

These tests:
- Build the Go binaries (`pilotctl`, `pilot-daemon`)
- Build the Python SDK wheel from source
- Install everything in a clean Alpine Linux container
- Start a real daemon and register on the network
- Test against **agent-alpha** (public demo agent with auto-accept enabled)
- Validate all CLI commands and SDK functionality
- Teardown and cleanup automatically

## Test Coverage

### CLI Tests (`test_cli.sh`)
Tests all `pilotctl` commands from the [CLI Reference](../../web/docs/cli-reference.html):

**Daemon Lifecycle:**
- `daemon start`, `daemon stop`, `daemon status`

**Identity & Discovery:**
- `info`, `set-hostname`, `clear-hostname`, `find`
- `set-public`, `set-private`
- `register`, `deregister`, `lookup`

**Communication:**
- `ping`, `connect`, `send`, `recv`, `listen`
- `send-message`, `send-file`
- `subscribe`, `publish`

**Built-in Services:**
- **Echo (port 7):** Latency and echo tests
- **Data Exchange (port 1001):** Text, JSON, binary, file transfers
- **Event Stream (port 1002):** Pub/sub events
- **Task Submit (port 1003):** Task submission

**Trust & Tags:**
- `trust`, `pending`, `approve`, `reject`, `untrust`
- `set-tags`, `clear-tags`

**Diagnostics:**
- `peers`, `connections`, `disconnect`
- `inbox`, `received`
- `config`

### SDK Tests (`test_sdk.py`)
Tests Python SDK against real daemon and network:

**Driver:**
- Connect to daemon via Unix socket
- Get agent info
- Resolve hostnames
- Ping peers
- Create connections and listeners

**Data Exchange:**
- Send/receive text messages
- Send/receive JSON data
- Send/receive binary data
- File transfer

**Event Stream:**
- Publish events to topics
- Subscribe to topics with wildcards
- Receive events

**Error Handling:**
- Invalid addresses
- Timeouts
- Connection failures

**Context Managers:**
- Automatic cleanup with `with` statements

## Running Tests

### Using Docker Compose (Recommended)

```bash
cd tests/integration

# Run all tests
docker-compose up --build

# Run and follow logs
docker-compose up --build --abort-on-container-exit

# Clean up
docker-compose down
```

Test results are saved to `tests/integration/results/`:
- `cli_results.txt` - CLI test output
- `sdk_results.txt` - SDK test output

### Using Docker Directly

```bash
# Build image
docker build -f tests/integration/Dockerfile -t pilot-integration-test .

# Run CLI tests only
docker run --rm pilot-integration-test /bin/bash /tests/test_cli.sh

# Run SDK tests only
docker run --rm pilot-integration-test python /tests/test_sdk.py

# Run all tests
docker run --rm pilot-integration-test
```

### Manual Testing (Without Docker)

```bash
# Ensure binaries are built
go build -o bin/pilotctl ./cmd/pilotctl
go build -o bin/pilot-daemon ./cmd/daemon

# Build Python SDK
cd sdk/python
./scripts/build.sh
pip install dist/*.whl
cd ../..

# Run tests
bash tests/integration/test_cli.sh
python tests/integration/test_sdk.py
```

## Test Agent

Tests communicate with **agent-alpha**, a public demo agent that:
- Runs 24/7 on the Pilot Protocol network
- Has auto-accept enabled (no handshake required)
- Accepts connections on all services
- Hostname: `agent-alpha`

## Test Architecture

```
┌─────────────────────────────────────┐
│  Docker Container (Alpine Linux)   │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  pilot-daemon (Go binary)    │  │
│  │  - Registered on network     │  │
│  │  - Unix socket: /tmp/pilot   │  │
│  └──────────────────────────────┘  │
│              ↕                      │
│  ┌──────────────────────────────┐  │
│  │  Test Scripts                │  │
│  │  - test_cli.sh (Bash)        │  │
│  │  - test_sdk.py (Python)      │  │
│  └──────────────────────────────┘  │
│              ↕                      │
│  ┌──────────────────────────────┐  │
│  │  pilotctl / Python SDK       │  │
│  │  - CLI commands              │  │
│  │  - CGO bindings              │  │
│  └──────────────────────────────┘  │
│              ↕                      │
└─────────────────────────────────────┘
              ↕
      (Internet - Real Network)
              ↕
┌─────────────────────────────────────┐
│      agent-alpha (Demo Agent)       │
│      - Public, auto-accept          │
│      - All services enabled         │
└─────────────────────────────────────┘
```

## Exit Codes

- `0` - All tests passed
- `1` - One or more tests failed

## Troubleshooting

**Container exits immediately:**
```bash
docker logs pilot-integration-test
```

**Daemon fails to start:**
- Check if port 9000 (registry) is accessible
- Verify network connectivity

**Cannot find agent-alpha:**
- Ensure container has internet access
- agent-alpha may be temporarily offline (rare)

**Tests timeout:**
- Increase timeout values in test scripts
- Check network latency

## CI/CD Integration

Add to GitHub Actions workflow:

```yaml
integration-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    
    - name: Run integration tests
      run: |
        cd tests/integration
        docker-compose up --build --abort-on-container-exit
        
    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: integration-test-results
        path: tests/integration/results/
```

## Adding New Tests

### CLI Test
Edit `test_cli.sh`:
```bash
log_test "Your new test"
if pilotctl your-command --args; then
    log_pass "Test passed"
else
    log_fail "Test failed"
fi
```

### SDK Test
Edit `test_sdk.py`:
```python
log_test("Your new test")
try:
    # Your test code
    log_pass("Test passed")
except Exception as e:
    log_fail(f"Test failed: {e}")
```

## Performance

Typical run time:
- CLI tests: ~30-45 seconds
- SDK tests: ~20-30 seconds
- Total: ~1 minute

## Cleanup

Tests automatically clean up:
- Stop daemon on exit
- Deregister from network
- Remove temporary files
- Kill background processes

Manual cleanup if needed:
```bash
docker-compose down -v
docker system prune -f
```
