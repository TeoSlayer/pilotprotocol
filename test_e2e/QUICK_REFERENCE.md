# Quick Reference: E2E Testing Commands

## System Status

All services are running:
- **Rendezvous** (registry + beacon): ports 14001, 14002
- **Alice daemon**: node_id=1, address 0:0000.0000.0001, socket /tmp/pilot-alice.sock
- **Bob daemon**: node_id=2, address 0:0000.0000.0002, socket /tmp/pilot-bob.sock

## Alice Commands (use these)

```bash
# Check status
cd /Users/alexgodo/web4/pilotprotocol/test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl status

# Establish trust with Bob
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl trust 0:0000.0000.0002

# Submit task to Bob
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node 0:0000.0000.0002 --task "Analyze logs for errors"

# Check Alice's inbox for results
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl inbox list

# Check karma score
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl karma
```

## Bob Commands (use these)

```bash
# Check status
cd /Users/alexgodo/web4/pilotprotocol/test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl status

# Establish trust with Alice
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl trust 0:0000.0000.0001

# View task queue
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl queue list

# Submit task to Alice (reverse direction)
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl submit-task --node 0:0000.0000.0001 --task "Collect system metrics"

# Check karma score
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl karma
```

## Monitoring Logs

```bash
# Watch Alice's daemon activity
tail -f /tmp/alice.log

# Watch Bob's daemon activity
tail -f /tmp/bob.log

# Watch Rendezvous activity
tail -f /tmp/rendezvous.log
```

## Testing Workflow

### 1. Establish Trust (required first)
```bash
# From Alice
cd /Users/alexgodo/web4/pilotprotocol/test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl trust 0:0000.0000.0002

# From Bob
cd /Users/alexgodo/web4/pilotprotocol/test_e2e/bob
PILOT_SOCKET=/tmp/pilot-bob.sock ./pilotctl trust 0:0000.0000.0001
```

### 2. Submit Tasks
```bash
# Alice submits to Bob
cd /Users/alexgodo/web4/pilotprotocol/test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl submit-task --node 0:0000.0000.0002 --task "Process dataset"
```

### 3. Watch Bob Process It
```bash
# Bob's daemon automatically processes tasks from queue (watch the log)
tail -f /tmp/bob.log
```

You'll see:
- `[DEBUG] Processing task from 0:0000.0000.0001: Process dataset`
- `[INFO] Mock task execution: sleeping for 2 seconds`
- `[INFO] Task completed successfully`
- `[INFO] Sending result to 0:0000.0000.0001 via data exchange`
- `[INFO] Karma updated: 0:0000.0000.0001 -1, 0:0000.0000.0002 +1`

### 4. Check Alice's Results
```bash
# Alice receives result asynchronously
cd /Users/alexgodo/web4/pilotprotocol/test_e2e/alice
PILOT_SOCKET=/tmp/pilot-alice.sock ./pilotctl inbox list
```

## Cleanup

```bash
# Stop all services
pkill -f rendezvous
pkill -f "daemon --config"

# Remove socket files
rm -f /tmp/pilot-alice.sock /tmp/pilot-bob.sock
```

## Key Observations

- Tasks require **mutual trust** between nodes
- Queue is **FIFO** - first in, first out
- Results delivered **asynchronously** via data exchange (port 1001)
- **Karma changes**: submitter -1, executor +1
- Mock tasks take ~2 seconds to execute
- All communication through localhost (127.0.0.1)
