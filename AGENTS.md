# AGENTS.md

## Project Overview
Pilot Protocol is an overlay network stack for AI agents. Written in Go (zero external dependencies). Each agent gets a 48-bit virtual address and communicates over encrypted UDP tunnels.

- Module: `github.com/TeoSlayer/pilotprotocol`
- License: AGPL-3.0
- Go version: 1.25.3

## Build & Test
```bash
go build ./...
go test -parallel 4 -count=1 ./tests/
```
Important: Always use `-parallel 4` — unlimited parallelism exhausts ports/sockets and causes dial timeouts.

## Directory Structure
```
cmd/           — Binary entry points (daemon, rendezvous, pilotctl, gateway)
pkg/           — Core libraries
  address/     — 48-bit virtual address encoding
  crypto/      — X25519+AES-GCM encryption, identity management
  header/      — 34-byte packet header (marshal/unmarshal)
  transport/   — Sliding window, congestion control, flow control
  tunnel/      — UDP tunnel with CRC32 integrity
  registry/    — Registry server + client (JSON over TCP)
  beacon/      — STUN + relay server for NAT traversal
  services/    — Built-in port services (echo:7, DNS:53, HTTP:80, etc.)
  ipc/         — Unix socket IPC between daemon and pilotctl
  trust/       — Handshake manager, trust state persistence
  nameserver/  — DNS-like hostname resolution
  pubsub/      — Topic-based publish/subscribe
tests/         — Integration tests
docs/          — Whitepaper, spec
web/           — Website (pilotprotocol.network)
ops/           — Deployment scripts
```

## Wire Format
- 34-byte packet header: Version(1) + Flags(1) + SrcAddr(6) + DstAddr(6) + SrcPort(2) + DstPort(2) + SeqNum(4) + AckNum(4) + Window(2) + Length(2) + Checksum(4)
- Address format: `N:NNNN.HHHH.LLLL` (16-bit network + 32-bit node)
- Tunnel magic bytes: `0x50494C54` ("PILT")
- CRC32 checksum for integrity

## Port Table
| Port | Service |
|------|---------|
| 7 | Echo |
| 53 | DNS |
| 80 | HTTP |
| 443 | Secure (X25519+AES-GCM) |
| 1000 | Stdio |
| 1001 | Data Exchange |
| 1002 | Event Stream |

## Critical Rules
1. **JSON float64 casting**: Go JSON numbers unmarshal as `float64` — always cast with `uint32(val.(float64))`
2. **STUN ordering**: STUN discovery must happen BEFORE starting the tunnel readLoop — they share the UDP socket and race
3. **Wildcard addresses**: `:PORT` and `0.0.0.0:PORT` must be resolved to `127.0.0.1:PORT` for local testing
4. **Registry mutex**: Registry client needs mutex on `Send()` — concurrent lookups interleave JSON on shared TCP
5. **IPC write mutex**: Multiple goroutines writing same IPC conn need a write mutex wrapper
6. **Linter caution**: The linter aggressively removes "unused" struct fields — don't store `crypto.Identity` in `NodeInfo`, use local vars instead

## Commit Rules
- Use imperative mood, under 72 chars for the first line
- Do NOT add Co-Authored-By lines or mention AI assistants
