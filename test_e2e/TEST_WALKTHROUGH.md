# End-to-End Task Submission Testing Guide

This guide walks you through testing the Task Submission Service with two simulated agents (alice and bob).

## Directory Structure

```
test_e2e/
├── alice/
│   ├── daemon          # Alice's daemon binary
│   ├── pilotctl        # Alice's CLI tool
│   └── daemon.json     # Alice's config (socket: /tmp/pilot-alice.sock, port: 55001)
├── bob/
│   ├── daemon          # Bob's daemon binary
│   ├── pilotctl        # Bob's CLI tool
│   └── daemon.json     # Bob's config (socket: /tmp/pilot-bob.sock, port: 55002)
├── rendezvous/
│   ├── rendezvous      # Combined registry + beacon server
│   └── rendezvous.json # Config (registry: 14001, beacon: 14002)
├── start_rendezvous.sh
├── start_alice.sh
└── start_bob.sh
```

## Step 1: Start the Rendezvous Server

The rendezvous server provides both registry (port 14001) and beacon (port 14002) services.

```bash
cd test_e2e
./start_rendezvous.sh
```

You should see output like:
```
Registry listening on 127.0.0.1:14001
Beacon listening on 127.0.0.1:14002
```

Leave this terminal running.

## Step 2: Start Alice's Daemon

Open a new terminal:

```bash
cd test_e2e
./start_alice.sh
```

You should see:
```
Daemon started
Socket: /tmp/pilot-alice.sock
Hostname: alice.pilot
Registry: 127.0.0.1:14001
```

Leave this terminal running.

## Step 3: Start Bob's Daemon

Open a third terminal:

```bash
cd test_e2e
./start_bob.sh
```

You should see:
```
Daemon started
Socket: /tmp/pilot-bob.sock
Hostname: bob.pilot
Registry: 127.0.0.1:14001
```

Leave this terminal running.

## Step 4: Test Basic Connectivity

In a new terminal (Terminal 4), verify both daemons are registered:

```bash
# As Alice, check node status
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl status

# As Bob, check node status
cd test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl status
```

Both should show they're connected to the registry.

## Step 5: Establish Trust Between Alice and Bob

Alice and Bob need to establish mutual trust before task submission works.

### From Alice's terminal (Terminal 4):
```bash
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl trust bob.pilot
```

Expected output:
```
Trust established with bob.pilot
```

### From Bob's terminal (Terminal 5 - new):
```bash
cd test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl trust alice.pilot
```

Expected output:
```
Trust established with alice.pilot
```

## Step 6: Submit a Task from Alice to Bob

Now Alice can submit tasks to Bob:

```bash
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node bob.pilot --task "Process image dataset"
```

Expected output:
```
Task submitted successfully
Status: 200
Message: Task accepted
Accepted: true
```

## Step 7: Verify Bob's Task Queue

Check Bob's queue to see the pending task:

```bash
cd test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl queue list
```

Expected output:
```
Task Queue (1 tasks):
1. From: alice.pilot
   Task: Process image dataset
   Submitted: 2026-02-16 18:30:45
```

## Step 8: Watch Task Processing

Bob's daemon automatically processes tasks from the queue in FIFO order. Watch Bob's daemon terminal to see:

```
[DEBUG] Processing task from alice.pilot: Process image dataset
[INFO] Mock task execution: sleeping for 2 seconds
[INFO] Task completed successfully
[INFO] Sending result to alice.pilot via data exchange
[INFO] Karma updated: alice.pilot -1, bob.pilot +1
```

## Step 9: Check Alice's Inbox for Results

Alice should receive the task result asynchronously:

```bash
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl inbox list
```

Expected output (JSON result):
```json
{
  "task_description": "Process image dataset",
  "status": "completed",
  "result": "Mock task completed successfully",
  "error": "",
  "timestamp": "2026-02-16T18:30:47Z"
}
```

## Step 10: Verify Karma Scores

Check karma scores in the registry:

```bash
# Alice's karma (should decrease by 1 for submitting)
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl karma

# Bob's karma (should increase by 1 for completing)
cd test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl karma
```

## Step 11: Test Multiple Tasks (FIFO Queue)

Submit multiple tasks from Alice to Bob:

```bash
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node bob.pilot --task "Task 1: Analyze logs"
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node bob.pilot --task "Task 2: Train model"
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node bob.pilot --task "Task 3: Generate report"
```

Check Bob's queue:
```bash
cd test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl queue list
```

Should show all 3 tasks in FIFO order. Bob's daemon will process them sequentially.

## Step 12: Test Reverse Direction (Bob → Alice)

Bob can also submit tasks to Alice:

```bash
cd test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl submit-task --node alice.pilot --task "Collect metrics"
```

Check Alice's queue:
```bash
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl queue list
```

## Step 13: Test Without Trust (Should Fail)

Start a third daemon (Charlie) without establishing trust:

```bash
# Create charlie's directory and config
mkdir -p test_e2e/charlie
cp test_e2e/alice/daemon test_e2e/charlie/
cp test_e2e/alice/pilotctl test_e2e/charlie/

# Create config (port 55003, socket /tmp/pilot-charlie.sock)
cat > test_e2e/charlie/daemon.json << EOF
{
  "registry": "127.0.0.1:14001",
  "beacon": "127.0.0.1:14002",
  "listen": ":55003",
  "socket": "/tmp/pilot-charlie.sock",
  "encrypt": false,
  "identity": "",
  "owner": "charlie",
  "hostname": "charlie.pilot",
  "log-level": "debug",
  "log-format": "text"
}
EOF

# Start charlie's daemon
cd test_e2e/charlie
./daemon --config daemon.json &

# Try to submit task without trust (should fail)
cd test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node charlie.pilot --task "Test task"
```

Expected output:
```
Task submission failed
Status: 400
Message: Trust not established
Accepted: false
```

## Cleanup

To stop all services:

```bash
# Kill all daemons and rendezvous
pkill -f "daemon --config"
pkill -f "rendezvous --config"

# Remove socket files
rm -f /tmp/pilot-*.sock
```

## Key Observations

1. **Trust Enforcement**: Tasks can only be submitted between mutually trusted nodes
2. **FIFO Queue**: Tasks are processed in the order they're received
3. **Async Results**: Task results are delivered asynchronously via data exchange (port 1001)
4. **Karma System**: Submitter loses 1 karma, executor gains 1 karma per task
5. **JSON Results**: Results are structured JSON with status, result, error, and timestamp
6. **Mock Execution**: Current implementation simulates task processing with 2-second delay
7. **Independent Sockets**: Each daemon has its own Unix socket for CLI communication
8. **Localhost Testing**: All communication happens on 127.0.0.1 (rendezvous + NAT traversal)

## Troubleshooting

- **"Connection refused"**: Make sure rendezvous is running first
- **"Trust not established"**: Run `pilotctl trust <node>` from both sides
- **"Socket not found"**: Make sure daemon is running and PILOT_SOCKET is set correctly
- **"Port already in use"**: Kill previous daemon instances with `pkill daemon`
