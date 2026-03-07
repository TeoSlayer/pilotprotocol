# Pilot Protocol Python SDK Examples

This directory contains examples demonstrating how to use the Pilot Protocol
Python SDK — from basic operations to advanced PydanticAI agent integration.

## Architecture

The Python SDK calls into the Go driver compiled as a C-shared library via
`ctypes`.  There is **no protocol reimplementation** in Python — Go is the
single source of truth.

```
Python script  →  pilotprotocol (ctypes)  →  libpilot.so  →  daemon
```

## Prerequisites

1. **Build the shared library:**
   ```bash
   make sdk-lib   # produces bin/libpilot.dylib (macOS) or bin/libpilot.so (Linux)
   ```

2. **Install the Python SDK:**
   ```bash
   pip install pilotprotocol
   # Or for development:
   pip install -e ../../sdk/python
   ```

3. **Start the Pilot Protocol daemon:**
   ```bash
   pilotctl daemon start --hostname my-agent
   ```

4. **For multi-agent examples, establish trust:**
   ```bash
   pilotctl handshake other-agent "collaboration"
   # Wait for approval or approve incoming requests
   pilotctl pending
   pilotctl approve <node_id>
   ```

## Examples Overview

### 1. Basic Usage (`basic_usage.py`)

Demonstrates fundamental SDK operations:
- Connecting to the daemon
- Getting node information
- Setting hostname and tags
- Resolving peer hostnames
- Trust management (handshake, approve, list trusted peers)
- Visibility control

```bash
python basic_usage.py
```

**Key patterns:**
```python
from pilotprotocol import Driver, PilotError

with Driver() as d:
    info = d.info()
    d.set_hostname("my-agent")
    d.set_tags(["python", "ml"])
    peers = d.trusted_peers()
```

---

### 2. Data Exchange Service (`data_exchange_demo.py`)

Shows how to use the Data Exchange service (port 1001) for typed communication:
- Send text messages
- Send JSON objects
- Transfer binary data
- Send files

```bash
python data_exchange_demo.py <peer-hostname-or-address>
```

**Key patterns:**
```python
# Send a datagram to peer's Data Exchange port
d.send_to("0:0001.0000.0002:1001", frame_bytes)
```

---

### 3. Event Stream Service (`event_stream_demo.py`)

Demonstrates pub/sub event messaging (port 1002):
- Publish events to topics
- Subscribe to specific topics
- Wildcard subscriptions
- Topic filtering

```bash
python event_stream_demo.py <peer> publish
python event_stream_demo.py <peer> subscribe
python event_stream_demo.py <peer> wildcard
python event_stream_demo.py <peer> filter
```

**Key patterns:**
```python
# Publish datagram
d.send_to(f"{peer_addr}:1002", event_frame)

# Subscribe via stream connection
with d.dial(f"{peer_addr}:1002") as conn:
    conn.write(subscription_frame)
    data = conn.read(4096)   # blocks until event arrives
```

---

### 4. Task Submit Service (`task_submit_demo.py`)

Shows agent-to-agent task delegation (port 1003):
- Submit tasks to worker agents
- Check polo score
- Handle task acceptance/rejection
- Security validation (dangerous task rejection)

```bash
python task_submit_demo.py <peer> submit
python task_submit_demo.py <peer> trust-check
```

**Key patterns:**
```python
# Open stream to Task Submit port, send request, read response
with d.dial(f"{peer_addr}:1003") as conn:
    conn.write(task_frame)
    response = conn.read(4096)
```

---

### 5. PydanticAI Agent (`pydantic_ai_agent.py`)

Integrates Pilot Protocol as tools for a PydanticAI agent:
- Discover peers by hostname
- Send messages to other agents
- Delegate tasks to workers
- Check network status
- Manage trust relationships

```bash
pip install pydantic-ai
python pydantic_ai_agent.py
```

**Key patterns:**
```python
from pydantic_ai import Agent, RunContext
from pilotprotocol import Driver

@agent.tool
def discover_peer(ctx: RunContext[PilotDependencies], hostname: str) -> dict:
    return ctx.deps.driver.resolve_hostname(hostname)
```

---

### 6. PydanticAI Multi-Agent (`pydantic_ai_multiagent.py`)

Advanced multi-agent collaboration system:
- Coordinator delegates research queries
- Researcher performs analysis
- Summariser synthesises results
- All communication over Pilot Protocol

```bash
pip install pydantic-ai
python pydantic_ai_multiagent.py
```

## API Quick Reference

| Old (async) | New (ctypes) |
|---|---|
| `await Driver.connect()` | `Driver()` |
| `async with await Driver.connect() as d:` | `with Driver() as d:` |
| `await d.info()` | `d.info()` |
| `await d.send_to(addr_obj, port, data)` | `d.send_to("N:XXXX.YYYY:PORT", data)` |
| `conn_id = await d.dial_addr(addr, port)` | `conn = d.dial("N:XXXX.YYYY:PORT")` |
| `await d.conn_send(conn_id, data)` | `conn.write(data)` |
| `await d.conn_close(conn_id)` | `conn.close()` (or use `with`) |
| `asyncio.run(main())` | `main()` |

## Error Handling

All SDK errors are raised as `PilotError`:

```python
from pilotprotocol import Driver, PilotError

try:
    with Driver() as d:
        d.resolve_hostname("nonexistent")
except PilotError as e:
    print(f"Error: {e}")
```

## Documentation

- **SDK Reference:** `sdk/python/README.md`
- **CLI Reference:** `examples/cli/BASIC_USAGE.md`
- **Protocol Spec:** `docs/SPEC.md`
- **Agent Skills:** `docs/SKILLS.md`
