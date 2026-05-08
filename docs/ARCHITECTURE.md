# Pilot Protocol — Architecture Reference

## Overview

Overlay network stack for AI agents. Pure Go, zero external dependencies, AGPL-3.0.
Permanent virtual addresses, encrypted UDP tunnels, decentralized trust, peer-to-peer communication.

## Directory Structure

```
cmd/           9 binaries (beacon, console, daemon, gateway, nameserver, pilot-admin, pilotctl, registry, rendezvous)
pkg/           15 library packages (protocol, daemon, driver, registry, beacon, gateway, secure, console, policy, etc.)
internal/      6 utility packages (account, crypto, fsutil, ipcutil, pool, validate)
tests/         87 test files, 1026 tests
examples/      3 categories: cli/, go/ (8 examples), python_sdk/ (6 scripts)
docs/          Spec, whitepaper, skills, diagrams
web/           Cloudflare Pages site (index.html, 32 doc pages, blog, playground)
scripts/       4 helper scripts (hooks, coverage badge, auto-accept, deploy)
configs/       3 JSON templates (daemon, gateway, rendezvous)
```

## Core Concepts

### Addressing (48-bit)
- Format: `[16-bit network][32-bit node]` → text: `N:NNNN.HHHH.LLLL`
- Special: Registry (0:1), Beacon (0:2), Nameserver (0:3), Broadcast (X:XXXX.FFFF.FFFF)
- ~4 billion nodes per network

### Packet Header (34 bytes)
```
Ver(4b) | Flags(4b) | Protocol(1B) | PayloadLen(2B)
SrcNet(2B) | SrcNode(4B) | DstNet(2B) | DstNode(4B)
SrcPort(2B) | DstPort(2B) | Seq(4B) | Ack(4B)
Window(2B) | Checksum(4B)
```
- Flags: SYN(0x1), ACK(0x2), FIN(0x4), RST(0x8)
- Protocols: Stream(1, TCP-like), Datagram(2, UDP-like), Control(3)
- Checksum: CRC32 IEEE

### Well-Known Ports
| Port | Service |
|------|---------|
| 7 | Echo |
| 53 | DNS (nameserver, WIP) |
| 80 | HTTP |
| 443 | Secure (X25519+AES-256-GCM) |
| 444 | Trust handshake |
| 1000 | StdIO |
| 1001 | Data exchange (typed frames) |
| 1002 | Event stream (pub/sub) |
| 1003 | Task submit |
| 1004 | Managed score |

### Tunnel Encapsulation
| Magic | Hex | Purpose |
|-------|-----|---------|
| PILT | 0x50494C54 | Plaintext packets |
| PILS | 0x50494C53 | Encrypted packets |
| PILK | 0x50494C4B | Key exchange |
| PILA | 0x50494C41 | Authenticated key exchange |
| PILP | 0x50494C50 | NAT punch packets |

### Transport Layer
- TCP-like: SYN/ACK handshake, sliding window, SACK, AIMD congestion control
- Flow control: 2-byte advertised receive window
- Nagle algorithm, auto segmentation, retransmission
- Keepalive: 30s probes, 120s idle timeout
- Graceful shutdown: FIN to all connections (registration preserved across restarts)

### Security
- Tunnel encryption (default): AES-256-GCM with X25519 key exchange, HKDF-SHA256 key derivation
- Per-connection encryption (port 443): additional X25519+AES-256-GCM layer with HKDF-SHA256
- GCM AAD: sender's node ID bound as additional authenticated data
- Identity: Ed25519 keypairs persisted to `~/.pilot/identity.json`
- Trust: mutual signed handshake, private-by-default nodes, registry pubkey verification
- Rate limiting: sliding window SYN limiter
- Admin token: constant-time compare, required for enterprise operations
- Replay protection: nonce cache (100K entries max) for secure channel

### NAT Traversal
- STUN discovery via beacon (UDP:9001)
- Hole-punching: MsgPunchRequest → MsgPunchCommand to both peers
- Relay fallback for symmetric NAT: MsgRelay wrapping
- Cloud VMs: `-endpoint host:port` skips STUN

### Registry
- Central TCP server (:9000): node lookup, hostname registration, network management
- Hot-standby replication: push-based snapshots, 15s heartbeat
- Persistence: atomic JSON snapshots
- Admin token for enterprise operations (constant-time compare)
- Enterprise: RBAC (owner/admin/member), network policies, audit trail
- Signature verification: Ed25519 signed operations (register, hostname, visibility, deregister)
- Nodes without public keys require admin token for authenticated operations

## Inter-Package Dependencies

```
protocol ← (foundation: types, constants, wire format)
  ↑
driver ← protocol, ipcutil (client SDK over Unix socket)
  ↑
secure ← (standalone: crypto/*, stdlib only)
  ↑
registry ← protocol, crypto, fsutil
beacon ← protocol
nameserver ← protocol, driver, fsutil
gateway ← protocol, driver
daemon ← protocol, driver, registry, beacon, secure, crypto, config, logging, pool, all service pkgs
console ← registry, crypto (admin web UI + API)
  ↑
dataexchange ← (standalone: io, encoding)
eventstream ← (standalone: io, encoding)
tasksubmit ← (standalone: io, encoding, json, math)
policy ← (standalone: json, expr/CEL)
config ← (standalone: flag, json)
logging ← (standalone: slog)
```
