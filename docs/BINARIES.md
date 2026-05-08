# Pilot Protocol — Binary Reference

## pilotctl (CLI Control Tool)

The main user-facing CLI for interacting with the Pilot Protocol daemon. Supports bootstrap, daemon lifecycle, registration, discovery, communication, tasks, trust, diagnostics, mailbox, gateway, and connection management. Global flag: `--json` for structured JSON output.

Full command reference: see [PILOTCTL-REFERENCE.md](PILOTCTL-REFERENCE.md).

---

## daemon

Core network daemon. Handles tunnel, registration, services.

### Flags
`--config`, `--registry` (34.71.57.205:9000), `--beacon` (34.71.57.205:9001), `--listen` (:0), `--socket` (/tmp/pilot.sock), `--endpoint <host:port>` (skip STUN), `--encrypt` (true), `--registry-tls`, `--registry-fingerprint`, `--identity`, `--email`, `--owner` (deprecated, use `--email`), `--keepalive` (30s), `--idle-timeout` (120s), `--syn-rate-limit` (100), `--max-conns-per-port` (1024), `--max-conns-total` (4096), `--time-wait` (10s), `--public`, `--hostname`, `--no-echo`, `--no-dataexchange`, `--no-eventstream`, `--no-tasksubmit`, `--webhook`, `--admin-token`, `--networks` (comma-separated network IDs to auto-join), `--log-level`, `--log-format`

### Built-in Services
- Port 7: Echo (disable: `--no-echo`)
- Port 1001: Data exchange (disable: `--no-dataexchange`)
- Port 1002: Event stream (disable: `--no-eventstream`)
- Port 1003: Task submit (disable: `--no-tasksubmit`)

---

## registry

Standalone registry server (TCP).

### Flags
`--config`, `--addr` (:9000), `--beacon` (34.71.57.205:9001), `--store` (JSON persistence), `--tls`, `--tls-cert`, `--tls-key`, `--log-level`, `--log-format`, `--admin-token`

---

## beacon

NAT traversal server (UDP). STUN discovery, hole-punching, relay, gossip clustering.

### Flags
`--config`, `--addr` (:9001), `--beacon-id`, `--peers` (gossip), `--health` (HTTP), `--registry`, `--log-level`, `--log-format`

---

## rendezvous

Combined registry + beacon. Primary deployment target.

### Flags
`--config`, `--registry-addr` (:9000), `--beacon-addr` (:9001), `--store`, `--tls`, `--tls-cert`, `--tls-key`, `--standby <primary:port>`, `--http` (dashboard), `--admin-token`, `--log-level`, `--log-format`

---

## gateway

IP-to-Pilot TCP bridge. Maps pilot addresses to local IPs.

### Subcommands
- `run [<pilot-addr> [<local-ip>]]...` — Start gateway
- `map <pilot-addr> [<local-ip>]` — Add mapping

### Flags
`--config`, `--socket`, `--subnet` (10.4.0.0/16), `--ports` (80,443,1000,1001,1002,7,8080,8443), `--log-level`, `--log-format`

---

## console

Web management console (HTTP). Provides a dashboard UI and Stripe billing integration for network and agent management.

### Flags
`--config`, `--addr` (:8080), `--db` (console.db), `--registry` (localhost:9000), `--admin-token`, `--stripe-secret-key`, `--stripe-webhook-secret`, `--stripe-network-price`, `--stripe-agent-price`, `--base-url` (http://localhost:8080), `--log-level`, `--log-format`

---

## pilot-admin

Admin CLI for registry network management. Requires `--registry` flag.

### Global Flags
`--registry` (required), `--token` (or env `PILOT_ADMIN_TOKEN`), `--version`

### Subcommands
- `create-network` — Create a new network. Flags: `--name` (required), `--node` (creator node ID, required), `--join-rule` (open|token|invite, default open), `--token`, `--enterprise`
- `list-networks` — List all networks
- `list-members` — List members of a network. Flag: `--network` (required)
- `list-nodes` — List all backbone nodes (requires admin token)
- `add-node` — Add a node to a network. Flags: `--network` (required), `--node` (required), `--token`, `--inviter`
- `remove-node` — Remove a node from a network. Flags: `--network` (required), `--node` (required)
- `delete-network` — Delete a network entirely. Flag: `--network` (required)

---

## nameserver (DISABLED)

Exits with "currently disabled (WIP)". Hostname discovery uses registry instead.
