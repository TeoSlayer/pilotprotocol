# Pilot Protocol Python SDK

[![PyPI version](https://img.shields.io/pypi/v/pilotprotocol)](https://pypi.org/project/pilotprotocol/)
[![Python versions](https://img.shields.io/pypi/pyversions/pilotprotocol)](https://pypi.org/project/pilotprotocol/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](htmlcov/index.html)
[![Tests](https://img.shields.io/badge/tests-61%20passing-success)](#testing)

Python client library for the Pilot Protocol network — giving AI agents permanent addresses, encrypted P2P channels, and a trust model.

## Architecture

**Single Source of Truth**: The Go `pkg/driver` package is compiled into a
C-shared library (`libpilot.so` / `.dylib` / `.dll`) and called from Python
via `ctypes`. Zero protocol reimplementation — every SDK call goes through the
same Go code the CLI uses.

```
┌─────────────┐    ctypes/FFI    ┌──────────────┐    Unix socket    ┌────────┐
│  Python SDK │ ───────────────► │  libpilot.so │ ─────────────────► │ Daemon │
│  (client.py)│                  │  (Go c-shared)│                   │        │
└─────────────┘                  └──────────────┘                    └────────┘
```

## Installation

```bash
pip install pilotprotocol
```

The installation process will automatically:
1. Install the Python SDK package
2. Download and install the Pilot Protocol daemon (`pilotctl`, `pilot-daemon`, `pilot-gateway`)
3. Set up the daemon as a system service (systemd on Linux, launchd on macOS)
4. Configure the default rendezvous server

**Platform Support:**
- Linux (x86_64, arm64)
- macOS (Intel, Apple Silicon)  
- Windows (x86_64) - experimental

## How It Works

When you run `pip install pilotprotocol`:
1. The wheel is downloaded and extracted to your Python environment
2. Entry points create console scripts: `pilotctl`, `pilot-daemon`, `pilot-gateway`
3. Binaries are bundled in the package at `site-packages/pilotprotocol/bin/`
4. On first command execution, `~/.pilot/config.json` is automatically created

### Binary Library

The SDK includes pre-built `libpilot` shared libraries for each platform. The library is automatically discovered at runtime from:
1. `~/.pilot/bin/` (pip install location via entry points)
2. The installed package directory (bundled in wheel)
3. `PILOT_LIB_PATH` environment variable (if set)
4. Development layout: `<project_root>/bin/`
5. System library search path

## Quick Start

```python
from pilotprotocol import Driver

# The daemon should already be running if installed via pip
# If not, start it: pilotctl daemon start --hostname my-agent

# Connect to local daemon
with Driver() as d:
    info = d.info()
    print(f"Address: {info['address']}")
    print(f"Hostname: {info.get('hostname', 'none')}")

    # Set hostname
    d.set_hostname("my-python-agent")

    # Discover a peer (requires mutual trust)
    peer = d.resolve_hostname("other-agent")
    print(f"Found peer: {peer['address']}")

    # Open a stream connection
    with d.dial(f"{peer['address']}:1000") as conn:
        conn.write(b"Hello from Python!")
        response = conn.read(4096)
        print(f"Got: {response}")
```

### First Time Setup

After installation, verify the daemon is running:

```bash
pilotctl daemon status

# If not running, start it:
pilotctl daemon start --hostname my-agent

# Check your node info:
pilotctl info
```

## Features

- **Single Source of Truth** — Go driver compiled as C-shared library
- **Synchronous API** — No async/await needed; simple blocking calls
- **Type safe** — Full type hints throughout
- **Zero Python dependencies** — Only `ctypes` (stdlib) + the shared library
- **Complete API** — All daemon commands: info, trust, streams, datagrams
- **Context managers** — `Driver`, `Conn`, and `Listener` all support `with`
- **Cross-platform** — Linux (.so), macOS (.dylib), Windows (.dll)

## Prerequisites

The daemon should be automatically installed and started when you `pip install pilotprotocol`.

To verify:
```bash
pilotctl daemon status
pilotctl info
```

If the daemon isn't running:
```bash
pilotctl daemon start --hostname my-agent
```

## API Overview

### Connection

```python
from pilotprotocol import Driver

# Default socket path
d = Driver()

# Custom socket path
d = Driver("/custom/path/pilot.sock")

# Context manager auto-closes
with Driver() as d:
    # ... use driver
```

### Identity & Discovery

```python
info = d.info()
# Returns: {"address": "0:0000.0000.0005", "hostname": "...", ...}

d.set_hostname("my-agent")
d.set_visibility(public=True)
d.set_tags(["python", "ml", "api"])

peer = d.resolve_hostname("other-agent")
# Returns: {"node_id": 7, "address": "0:0000.0000.0007"}
```

### Trust Management

```python
d.handshake(peer_node_id, "collaboration request")
pending = d.pending_handshakes()
d.approve_handshake(node_id)
d.reject_handshake(node_id, "reason")
trusted = d.trusted_peers()
d.revoke_trust(node_id)
```

### Stream Connections

```python
# Client: dial a remote address
with d.dial("0:0001.0000.0002:8080") as conn:
    conn.write(b"Hello!")
    data = conn.read(4096)

# Server: listen on a port
with d.listen(8080) as ln:
    with ln.accept() as conn:
        data = conn.read(4096)
        conn.write(b"Echo: " + data)
```

### Unreliable Datagrams

```python
# Send datagram (addr format: "N:XXXX.YYYY.YYYY:PORT")
d.send_to("0:0001.0000.0002:9090", b"fire and forget")

# Receive next datagram (blocks)
dg = d.recv_from()
# Returns: {"src_addr": "...", "src_port": 8080, "dst_port": 9090, "data": ...}
```

### Configuration

```python
d.set_webhook("http://localhost:8080/events")
d.set_task_exec(enabled=True)
d.deregister()
d.disconnect(conn_id)
```

## Error Handling

```python
from pilotprotocol import Driver, PilotError

try:
    with Driver() as d:
        peer = d.resolve_hostname("unknown")
except PilotError as e:
    print(f"Pilot error: {e}")
```

All errors from the Go layer are raised as `PilotError`.

## Library Discovery

The SDK searches for `libpilot.{so,dylib,dll}` in this order:

1. `PILOT_LIB_PATH` environment variable (explicit path)
2. Same directory as `client.py` (pip wheel layout)
3. `<project_root>/bin/` (development layout)
4. System library search path

## Examples

See `examples/python_sdk/` for comprehensive examples:

- **`basic_usage.py`** — Connection, identity, trust management
- **`data_exchange_demo.py`** — Send messages, files, JSON
- **`event_stream_demo.py`** — Pub/sub patterns
- **`task_submit_demo.py`** — Task delegation and polo score
- **`pydantic_ai_agent.py`** — PydanticAI integration with function tools
- **`pydantic_ai_multiagent.py`** — Multi-agent collaboration system

## Testing

```bash
cd sdk/python
python -m pytest tests/ -v
```

47 tests cover all wrapper methods, error handling, and library discovery.

## Development

```bash
# Build shared library
make sdk-lib

# Install SDK in development mode
cd sdk/python && pip install -e .

# Run tests
pytest tests/ -v
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Repository structure
- Development setup
- Testing guidelines
- Building and publishing to PyPI
- Code quality standards

Quick commands:
```bash
make install-dev      # Install with dev dependencies
make test             # Run tests
make test-coverage    # Run tests with coverage
make coverage-badge   # Generate coverage badge
make build            # Build wheel and sdist
make publish-test     # Publish to TestPyPI
```

## Documentation

- **Examples:** `examples/python_sdk/README.md`
- **CLI Reference:** `examples/cli/BASIC_USAGE.md`
- **Protocol Spec:** `docs/SPEC.md`
- **Agent Skills:** `docs/SKILLS.md`

## License

AGPL-3.0 — See LICENSE file
