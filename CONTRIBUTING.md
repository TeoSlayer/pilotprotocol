# Contributing to Pilot Protocol

Thank you for your interest in contributing to Pilot Protocol. This document covers guidelines and instructions for contributing.

## Getting Started

### Prerequisites

- Go 1.21 or later
- Git

### Setup

```bash
git clone git clone git@github.com:TeoSlayer/pilotprotocol.git
cd pilotprotocol
go build ./...
```

### Running Tests

```bash
go test -parallel 4 -count=1 ./tests/
```

The `-parallel 4` flag is required. Unlimited parallelism exhausts ports and sockets, causing dial timeouts and flaky failures.

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
tests/                  # Integration tests (39 test files, 202+ passing)
docs/                   # Documentation
  SPEC.md               # Wire specification
  WHITEPAPER.pdf        # Protocol whitepaper (LaTeX source: WHITEPAPER.tex)
  SKILLS.md             # Agent skill definition
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

- **Nameserver** (port 53): DNS-equivalent name resolution is WIP and needs implementation
- **Tests**: expanding coverage, especially for edge cases in transport and security
- **Documentation**: improving examples, tutorials, architecture docs
- **Performance**: profiling and optimizing the transport layer
- **Platform support**: testing on different OS/architectures

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
