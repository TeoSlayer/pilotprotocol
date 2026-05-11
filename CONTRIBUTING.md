# Contributing to Pilot Protocol

Thank you for your interest in contributing to Pilot Protocol. This document covers guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Go 1.25 or later
- Git

### Setup

```bash
git clone git@github.com:TeoSlayer/pilotprotocol.git
cd pilotprotocol
go build ./...
```

### Running Tests

```bash
go test -parallel 4 -count=1 ./tests/
```

The `-parallel 4` flag is required. Unlimited parallelism exhausts ports and sockets, causing dial timeouts and flaky failures.

#### Integration Tests

Full integration tests against a real test network are available using Docker:

```bash
cd tests/integration
make test                # Run all integration tests
make test-cli            # Run CLI tests only
make test-sdk            # Run Python SDK tests only
```

These tests validate the entire stack (Go binaries + Python SDK) against **agent-alpha**, a public demo agent running on the network. See [tests/integration/README.md](tests/integration/README.md) for details.

### Project Structure

```
cmd/                    # Binary entry points
  daemon/               # Core network daemon
  pilotctl/             # CLI tool
  rendezvous/           # Combined registry + beacon server
  gateway/              # IP-to-Pilot bridge
  registry/             # Standalone registry (split deployment)
  beacon/               # Standalone beacon (split deployment)
  nameserver/           # DNS-equivalent nameserver (WIP)
pkg/                    # Library packages
  protocol/             # Wire format, addresses, headers, checksums
  daemon/               # Daemon core: connections, ports, transport, services
  driver/               # Client-side IPC driver (Unix socket)
  registry/             # Registry server + client + replication
  beacon/               # STUN-based NAT traversal
  gateway/              # TCP-to-Pilot proxy bridge
  secure/               # X25519 + AES-256-GCM encrypted connections
  dataexchange/         # Typed frame protocol (port 1001)
  eventstream/          # Pub/sub event broker (port 1002)
  nameserver/           # DNS-equivalent name resolution (WIP)
  config/               # JSON config file support
  logging/              # Structured logging setup (slog)
examples/               # Example applications
  echo/                 # Standalone echo server (now built into daemon)
  webserver/            # HTTP server over Pilot port 80
  dataexchange/         # Data exchange client
  eventstream/          # Event stream pub/sub client
  client/               # Basic client example
  httpclient/           # HTTP client over Pilot
  secure/               # Secure connection example
  config/               # Config file example
sdk/                    # Language SDKs
  python/               # Python SDK (see sdk/python/CONTRIBUTING.md)
  cgo/                  # CGO bindings
tests/                  # Integration tests (39 test files, 202+ passing)
docs/                   # Documentation
  SPEC.md               # Wire specification
  WHITEPAPER.pdf        # Protocol whitepaper (LaTeX source: WHITEPAPER.tex)
```

## Lock discipline (required reading for registry/daemon contributors)

The registry holds several mutexes covering different scopes. Running
signature-verification work — or any operation that can take longer than
a few microseconds — while holding a global lock can produce contention
queues large enough to drop the registry over a cliff under load.

The 3-phase pattern is: **RLock → unlock → verify (signatures, args,
caller identity) → Lock for mutation only**. The verify phase must not
hold any registry mutex.

Concrete rules:

1. **Never call `crypto`/`subtle.ConstantTimeCompare`/JSON-marshal
   under `s.mu`.** These can take microseconds-to-milliseconds; a
   queue of contended writers piles up behind them.
2. **Bracket `s.mu` write windows tightly** — only the actual map
   mutation goes under `s.mu.Lock()`. Read inputs first under RLock,
   verify, then take the write lock.
3. **Snapshot/replication paths build their deep-copy outside `s.mu`.**
   See `apply_snapshot_test.go` for the lock-hold regression test.
4. **List endpoints (`list_nodes`, `list_networks`) go through the
   singleflight cache.** Re-marshalling JSON for every caller while
   `s.mu` is held drives global-lock contention to a cliff under load.

## Contributing to the Python SDK

See the **[Python SDK Contributing Guide](sdk/python/CONTRIBUTING.md)**.

Quick start for Python SDK development:
```bash
cd sdk/python
python -m venv venv
source venv/bin/activate
pip install -e .[dev]
make test
```

## How to Contribute

### Reporting Issues

- Check existing issues first to avoid duplicates
- Include Go version, OS, and steps to reproduce
- For test failures, include the full test output with `-v` flag

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Write your changes
4. Add or update tests as needed
5. Ensure all tests pass: `go test -parallel 4 -count=1 ./tests/`
6. Ensure the project builds: `go build ./...`
7. Submit a pull request with a clear description

### Testing publish workflows (`ci_*` branches)

`Publish Python SDK` and `Publish Node SDK` normally only fire on
`release: published` events. Iterating on these workflows by cutting real
releases is slow and side-effecting (every test wheel/npm package would
be a permanent public artifact).

**The convention: branches whose name starts with `ci_` get a permanent
dry-run on every push.** A push to `ci_*` runs everything through the
build jobs, the version-stamp assertions, and the dry-pack — but stops
before the actual `twine upload` / `npm publish` steps. The publish jobs
are gated on `github.event_name == 'release'`, so a push rehearsal never
touches PyPI or npm.

How it works:
- On a release event, the workflows pull binaries from that release's tag.
- On a `ci_*` push, they pull binaries from the **latest existing**
  release (resolved via `gh release view --json tagName`) and use that as
  the rehearsal target. This means: there must be at least one prior
  release on GitHub for the rehearsal to have something to pull from.

Naming:
- `ci_workflow_iter` — fine
- `ci_test_build_libpilot` — fine
- `feature/ci-test` — **does not match**; the rehearsal trigger pattern is
  `ci_*` literally. Any other branch name is silently ignored by the
  publish workflows.

Tip: use `gh run watch` after pushing to follow the run, and
`gh run view --log-failed` to retrieve only failed-step logs.

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep functions focused and small
- Use `slog` for structured logging (not `log` or `fmt.Printf` for runtime output)
- Error messages should be lowercase without trailing punctuation
- Use the existing patterns in the codebase as reference

### Testing Guidelines

- All new features should have integration tests in `tests/`
- Tests use the `TestEnv` helper (`tests/testenv.go`) which spins up in-process daemons
- If your feature adds a built-in service or uses a well-known port, add a `Disable*` config field and use it in tests that bind those ports via driver
- Use `t.Parallel()` in all test functions
- Use timeouts on all blocking operations (channels, reads) to prevent hung tests
- Prefer table-driven tests for multiple input variations

### Architecture Notes

- The daemon is the only process agents need to run. Built-in services (echo, data exchange, event stream) start automatically
- All daemon interaction goes through the IPC socket (Unix domain socket). The `driver` package provides the client side; the `daemon/ipc.go` provides the server side
- The transport layer implements TCP-like semantics: SYN/ACK handshake, sliding window, SACK, congestion control (AIMD), flow control, Nagle, retransmission
- Security is layered: tunnel-level encryption (all traffic between two daemons) and connection-level encryption (port 443, per-connection X25519 + AES-GCM)
- Trust is privacy-first: nodes are private by default, mutual handshake required, signed with Ed25519

### Commit Messages

- Use imperative mood: "Add feature" not "Added feature"
- First line: concise summary under 72 characters
- Body (optional): explain the why, not just the what

## Areas for Contribution

- **Python SDK**: Improve the Python SDK, add examples, enhance documentation (see [sdk/python/CONTRIBUTING.md](sdk/python/CONTRIBUTING.md))
- **Nameserver** (port 53): DNS-equivalent name resolution is WIP and needs implementation
- **Tests**: expanding coverage, especially for edge cases in transport and security
- **Documentation**: improving examples, tutorials, architecture docs
- **Performance**: profiling and optimizing the transport layer
- **Platform support**: testing on different OS/architectures
- **Language SDKs**: Create SDKs for other languages (JavaScript, Rust, Java, etc.)

## License

By contributing to Pilot Protocol, you agree that your contributions will be licensed under the [GNU Affero General Public License v3.0](LICENSE).


---

## Development

### Running tests

```bash
make test              # Run all tests
make coverage          # Run tests with coverage and update badge
make coverage-html     # Generate HTML coverage report
```

### Pre-commit hooks

Set up automatic code quality checks before each commit:

```bash
./scripts/setup-hooks.sh
```

This installs a git hook that automatically runs:
- `go fmt` - Code formatting
- `go vet` - Static analysis
- `go test` - All tests
- Coverage badge update

To skip the hook temporarily: `git commit --no-verify`
