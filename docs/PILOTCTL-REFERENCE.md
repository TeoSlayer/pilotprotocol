# Pilot Protocol — pilotctl Command Reference

Every command's exact JSON output format, IPC mapping, and behavior.

## Contents

- [Global](#global) — JSON output, env vars, error codes
- [Bootstrap](#bootstrap) — init, config, context
- [Daemon Lifecycle](#daemon-lifecycle) — start, stop, status
- [Registry Operations](#registry-operations) — register, lookup, rotate-key, visibility
- [Discovery](#discovery) — find, set-hostname, tags, tasks, webhook
- [Communication](#communication) — connect, send, recv, send-file, send-message, subscribe, publish
- [Task Commands](#task-commands) — submit, accept, decline, execute, send-results, list, queue
- [Trust Commands](#trust-commands) — handshake, approve, reject, untrust, pending, trust
- [Network Commands](#network-commands) — list, join, leave, members, invite, create, delete, etc.
- [Enterprise Admin](#enterprise-admin) — audit, provision, idp, audit-export, directory-sync, directory-status
- [Diagnostics](#diagnostics) — info, health, peers, connections, ping, bench, traceroute
- [Gateway Commands](#gateway-commands) — start, stop, map, unmap, list
- [Mailbox](#mailbox) — received, inbox

## Global

- `--json` flag on all commands → `{"status": "ok", "data": {...}}` or `{"status": "error", "code": "<code>", "message": "<msg>"}`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PILOT_REGISTRY` | `34.71.57.205:9000` | Registry address |
| `PILOT_SOCKET` | `/tmp/pilot.sock` | Daemon IPC socket path |
| `PILOT_ADMIN_TOKEN` | *(none)* | Admin token for enterprise operations |

All three can also be set in `~/.pilot/config.json` (keys: `registry`, `socket`, `admin_token`). Environment variables take precedence over config file values.

## Error Codes

| Code | Meaning |
|------|---------|
| `invalid_argument` | Bad input (no retry) |
| `not_found` | Resource missing (no retry) |
| `already_exists` | Duplicate operation (no retry) |
| `not_running` | Service unavailable (check & retry) |
| `connection_failed` | Network error (may retry) |
| `timeout` | Operation timed out (may retry) |
| `auth_required` | Admin token required for this operation |
| `unavailable` | Feature not yet available |
| `internal` | System error (may retry) |

---

## Bootstrap

### `pilotctl init`
Initialize config at `~/.pilot/config.json`.
**Flags:** `--registry`, `--beacon`, `--hostname`, `--socket`
```json
{"status": "ok", "data": {"config_path": "~/.pilot/config.json", "registry": "34.71.57.205:9000", "beacon": "127.0.0.1:9001", "socket": "/tmp/pilot.sock", "hostname": ""}}
```

### `pilotctl config`
Show/set config.
**Flag:** `--set key=value`

Show: returns all config values plus `config_path`, `pid_file`, `log_file`.
Set: returns `{"key": "...", "value": "..."}`.

### `pilotctl context`
Dump full command list as JSON (agent tool discovery). Returns version, all commands with args/description/returns, error codes, global flags, environment variables, and config file path.

---

## Daemon Lifecycle

### `pilotctl daemon start`

Forks background daemon process. Blocks until registered, then prints status and exits.

**Flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--config` | *(none)* | Path to JSON config file |
| `--registry` | from config or `34.71.57.205:9000` | Registry address |
| `--beacon` | from config or `127.0.0.1:9001` | Beacon/STUN address |
| `--listen` | `:0` | Local UDP listen address |
| `--identity` | `~/.pilot/identity.json` | Path to identity keypair |
| `--email` | from config | Owner email (mandatory for registration) |
| `--hostname` | from config | Node hostname |
| `--log-level` | `info` | Log level (debug, info, warn, error) |
| `--log-format` | `text` | Log format (text, json) |
| `--public` | `false` | Make node publicly visible |
| `--foreground` | `false` | Run in foreground (don't fork) |
| `--no-encrypt` | `false` | Disable tunnel encryption |
| `--socket` | from config or `/tmp/pilot.sock` | IPC socket path |
| `--webhook` | from config | Webhook URL for event notifications |
| `--admin-token` | from config | Admin token for enterprise operations |
| `--networks` | from config | Comma-separated network IDs to auto-join |

**Note:** `--owner` is accepted as a backward-compatible alias for `--email`.

**Output:**
```json
{"status": "ok", "data": {"node_id": 42, "address": "0:0000.0000.002A", "pid": 12345, "socket": "/tmp/pilot.sock", "hostname": "mynode", "log_file": "~/.pilot/pilot.log"}}
```

### `pilotctl daemon stop`
```json
{"status": "ok", "data": {"pid": 12345, "forced": false}}
```

### `pilotctl daemon status`
**Flag:** `--check` (silent health check — exits 0 if daemon is responsive, exits 1 otherwise)
```json
{"status": "ok", "data": {"running": true, "responsive": true, "pid": 12345, "pid_file": "~/.pilot/pilot.pid", "socket": "/tmp/pilot.sock", "node_id": 42, "address": "0:0000.0000.002A", "hostname": "mynode", "uptime_secs": 3600, "peers": 8, "connections": 5}}
```

---

## Registry Operations

### `pilotctl register [listen_addr]`
```json
{"status": "ok", "data": {"node_id": 42, "address": "0:0000.0000.002A", "public_key": "base64"}}
```

### `pilotctl lookup <node_id>`
```json
{"status": "ok", "data": {"node_id": 42, "address": "0:0000.0000.002A", "hostname": "mynode", "public": true, "real_addr": "1.2.3.4:4000"}}
```

### `pilotctl rotate-key <node_id> <email>`
```json
{"status": "ok", "data": {"node_id": 42, "address": "...", "public_key": "base64"}}
```

### `pilotctl set-public` / `set-private`
Routes through daemon IPC (`driver.SetVisibility(true/false)`).
```json
{"status": "ok", "data": {"visibility": "public"}}
```

### `pilotctl deregister`
Routes through daemon IPC (`driver.Deregister()`).
```json
{"status": "ok", "data": {"deregistered": true}}
```

---

## Discovery

### `pilotctl find <hostname>`
```json
{"status": "ok", "data": {"node_id": 42, "address": "0:0000.0000.002A", "hostname": "mynode", "public": true}}
```
IPC: `driver.ResolveHostname(hostname)`

### `pilotctl set-hostname <hostname>`
```json
{"status": "ok", "data": {"hostname": "mynode"}}
```
IPC: `driver.SetHostname(hostname)`

### `pilotctl clear-hostname`
IPC: `driver.SetHostname("")`

### `pilotctl set-tags <tag1> [tag2]...`
```json
{"status": "ok", "data": {"tags": ["tag1", "tag2"]}}
```
IPC: `driver.SetTags(tags)`

### `pilotctl clear-tags`
IPC: `driver.SetTags([])`

### `pilotctl enable-tasks` / `disable-tasks`
```json
{"status": "ok", "data": {"task_exec": true}}
```
IPC: `driver.SetTaskExec(true/false)`

### `pilotctl set-webhook <url>` / `clear-webhook`
```json
{"status": "ok", "data": {"webhook": "https://example.com/hook"}}
```
IPC: `driver.SetWebhook(url)`

---

## Communication

### `pilotctl connect <addr|hostname> [port]`
**Flags:** `--message`, `--timeout`

Interactive mode (no `--message`): stdin/stdout bidirectional.
Message mode: sends, reads response, exits.

```json
{"status": "ok", "data": {"target": "0:0000.0000.000B", "port": 1000, "sent": "hello", "response": "hello"}}
```
IPC: `driver.DialAddr(target, port)` → `conn.Write()` → `conn.Read()`

### `pilotctl send <addr|hostname> <port> --data <msg>`
**Flags:** `--data` (required), `--timeout`
```json
{"status": "ok", "data": {"target": "0:0000.0000.000B", "port": 1000, "sent": "hello", "response": "world"}}
```

### `pilotctl recv <port>`
**Flags:** `--count`, `--timeout`
```json
{"status": "ok", "data": {"messages": [{"seq": 0, "port": 1000, "data": "hello", "bytes": 5}], "timeout": false}}
```
IPC: `driver.Listen(port)` → `ln.Accept()` → `conn.Read()`

### `pilotctl send-file <addr|hostname> <filepath>`
```json
{"status": "ok", "data": {"filename": "doc.pdf", "bytes": 102400, "destination": "0:0000.0000.000B", "ack": "received"}}
```
IPC: `dataexchange.Dial()` → `client.SendFile()` → `client.Recv()`

### `pilotctl send-message <addr|hostname> --data <text>`
**Flags:** `--data` (required), `--type text|json|binary`
```json
{"status": "ok", "data": {"target": "0:0000.0000.000B", "type": "json", "bytes": 256, "ack": "received"}}
```

### `pilotctl subscribe <addr|hostname> <topic>`
**Flags:** `--count`, `--timeout`

Streaming (unbounded, NDJSON):
```json
{"topic": "updates", "data": "new event", "bytes": 9}
```

Bounded (`--count`):
```json
{"status": "ok", "data": {"events": [{"topic": "updates", "data": "event1", "bytes": 6}], "timeout": false}}
```

### `pilotctl publish <addr|hostname> <topic> --data <msg>`
```json
{"status": "ok", "data": {"target": "0:0000.0000.000B", "topic": "updates", "bytes": 11}}
```

---

## Task Commands

### `pilotctl task submit <addr|hostname> --task <description>`
```json
{"status": "ok", "data": {"target": "0:0000.0000.000B", "task_id": "uuid", "task": "compute fibonacci", "status": "accepted", "message": "Task accepted", "accepted": true}}
```
Saves to `~/.pilot/tasks/submitted/<task_id>.json`. IPC: `tasksubmit.Dial()` → `client.SubmitTask()`

### `pilotctl task accept --id <task_id>`
```json
{"status": "ok", "data": {"task_id": "uuid", "status": "ACCEPTED", "message": "Task accepted"}}
```
Validates status NEW, checks 1-minute deadline, calculates `time_idle`. Sends StatusAccepted to submitter.

### `pilotctl task decline --id <task_id> --justification <reason>`
```json
{"status": "ok", "data": {"task_id": "uuid", "status": "DECLINED", "justification": "resource unavailable", "message": "Task declined"}}
```

### `pilotctl task execute`
No args — picks first ACCEPTED task.
```json
{"status": "ok", "data": {"task_id": "uuid", "task_description": "compute fibonacci", "status": "EXECUTING", "from": "0:0000.0000.000A"}}
```
Calculates `time_staged`. Sends StatusExecuting to submitter.

### `pilotctl task send-results --id <task_id>`
**Flags:** `--results <text>` OR `--file <filepath>`

**File restrictions:** Allowed: .pdf, .txt, .md, .csv, .xlsx, .jpg, .png, .zip. Forbidden: .py, .js, .go, .java, .sh, .sql etc.

```json
{"status": "ok", "data": {"task_id": "uuid", "status": "SUCCEEDED", "sent_to": "0:0000.0000.000A", "sent_type": "text"}}
```
Creates `TaskResultMessage` with timing metadata (idle/staged/cpu ms) for polo score calculation.

### `pilotctl task list`
**Flags:** `--type received|submitted`
```json
{"status": "ok", "data": {"tasks": [{"task_id": "uuid", "description": "...", "status": "ACCEPTED", "from": "...", "to": "...", "created_at": "RFC3339", "category": "received"}]}}
```

### `pilotctl task queue`
```json
{"status": "ok", "data": {"queue": [{"task_id": "uuid", "description": "...", "from": "...", "created_at": "RFC3339"}], "count": 1}}
```

**Task file format** (`~/.pilot/tasks/received/<task_id>.json`):
```json
{"task_id": "uuid", "task_description": "...", "status": "ACCEPTED", "from": "...", "to": "...", "created_at": "RFC3339", "time_idle_ms": 1000, "time_staged_ms": 500, "time_cpu_ms": 0}
```

---

## Trust Commands

### `pilotctl handshake <node_id|hostname> [justification]`
```json
{"status": "ok", "data": {"status": "pending", "node_id": 11}}
```
IPC: `driver.Handshake(nodeID, justification)`

### `pilotctl approve <node_id>`
```json
{"status": "ok", "data": {"status": "ok", "node_id": 11}}
```
IPC: `driver.ApproveHandshake(nodeID)`

### `pilotctl reject <node_id> [reason]`
```json
{"status": "ok", "data": {"status": "ok", "node_id": 11}}
```
IPC: `driver.RejectHandshake(nodeID, reason)`

### `pilotctl untrust <node_id>`
```json
{"status": "ok", "data": {"node_id": 11}}
```
IPC: `driver.RevokeTrust(nodeID)`

### `pilotctl pending`
```json
{"status": "ok", "data": {"pending": [{"node_id": 11, "justification": "collaborative work", "received_at": 1709010000}]}}
```

### `pilotctl trust`
```json
{"status": "ok", "data": {"trusted": [{"node_id": 11, "mutual": true, "network": 0, "approved_at": 1709010000}]}}
```

---

## Network Commands

### `pilotctl network list`
Lists networks the daemon belongs to.
```json
{"status": "ok", "data": {"networks": [{"id": 1, "name": "my-network", "join_rule": "open", "members": 5}]}}
```
IPC: `driver.NetworkList()`

### `pilotctl network join <network_id> [--token TOKEN]`
Join a network. Token required if the network's join rule is `token`.
```json
{"status": "ok", "data": {"joined": true}}
```
IPC: `driver.NetworkJoin(netID, token)`

### `pilotctl network leave <network_id>`
Leave a network.
IPC: `driver.NetworkLeave(netID)`

### `pilotctl network members <network_id>`
List members of a network.
```json
{"status": "ok", "data": {"nodes": [{"node_id": 42, "hostname": "mynode", "public": true}]}}
```
IPC: `driver.NetworkMembers(netID)`

### `pilotctl network invite <network_id> <node_id>`
Invite a node to join a network.
IPC: `driver.NetworkInvite(netID, nodeID)`

### `pilotctl network invites`
List pending network invitations for this node.
```json
{"status": "ok", "data": {"invites": [{"network_id": 1, "inviter_id": 42, "timestamp": "RFC3339"}]}}
```
IPC: `driver.NetworkPollInvites()`

### `pilotctl network accept <network_id>`
Accept a pending network invite.
IPC: `driver.NetworkRespondInvite(netID, true)`

### `pilotctl network reject <network_id>`
Reject a pending network invite.
IPC: `driver.NetworkRespondInvite(netID, false)`

### Enterprise Network Operations

The following commands go directly to the registry and require `PILOT_ADMIN_TOKEN`.

### `pilotctl network create --name <name> [--join-rule open|token|invite] [--token T] [--enterprise] [--node-id N] [--network-admin-token T]`
Create a new network. Requires admin token.
```json
{"status": "ok", "data": {"network_id": 1, "name": "my-network", "join_rule": "open", "enterprise": false}}
```

### `pilotctl network delete <network_id>`
Delete a network. Requires admin token.

### `pilotctl network rename <network_id> <new_name>`
Rename a network. Requires admin token.

### `pilotctl network promote <network_id> <target_node_id>`
Promote a member to admin. Requires admin token.

### `pilotctl network demote <network_id> <target_node_id>`
Demote an admin to member. Requires admin token.

### `pilotctl network kick <network_id> <target_node_id>`
Remove a member from a network. Requires admin token.

### `pilotctl network role <network_id> <node_id>`
Query a member's role in a network.
```json
{"status": "ok", "data": {"role": "admin"}}
```

### `pilotctl network policy <network_id> [--set ...]`
Get or set a network's policy. Setting requires admin token.
**Set flags:** `--max-members <n>`, `--description <text>`, `--allowed-ports <comma-separated>`
```json
{"status": "ok", "data": {"max_members": 100, "description": "My network", "allowed_ports": [7, 80, 443]}}
```

---

## Managed Network Commands

### `pilotctl managed score <peer_node_id> [--net <id>] [--topic T] [--delta N]`
Score a peer in a managed network. Default delta: 1.
```json
{"status": "ok", "data": {"node_id": 42, "delta": 1, "topic": ""}}
```
IPC: `driver.ManagedScore(netID, nodeID, delta, topic)`

### `pilotctl managed status [--net <id>]`
Show managed network status for this node.
IPC: `driver.ManagedStatus(netID)`

### `pilotctl managed rankings [--net <id>]`
Display peer rankings in the managed network.
IPC: `driver.ManagedRankings(netID)`

### `pilotctl managed cycle --force [--net <id>]`
Force a managed network evaluation cycle. `--force` is required.
```json
{"status": "ok", "data": {"pruned": 2, "filled": 1, "peers": 8}}
```
IPC: `driver.ManagedForceCycle(netID)`

---

## Policy Commands

### `pilotctl policy get --net <id>`
Retrieve the active policy for a network.
IPC: `driver.PolicyGet(netID)`

### `pilotctl policy set --net <id> --file <path>` / `--inline '<json>'`
Apply a policy document to a network. Validates and compiles locally (CEL) before applying.
```json
{"status": "ok", "data": {"applied": true, "rules": 5}}
```
IPC: `driver.PolicySet(netID, policyJSON)`

### `pilotctl policy validate --file <path>` / `--inline '<json>'`
Validate a policy document without applying it. Returns rule count and compilation status.
```json
{"status": "ok", "data": {"valid": true, "rules": 5, "events": ["connect", "cycle"]}}
```

### `pilotctl policy test --file <path> --event '<json>'`
Test a policy against a simulated event. Returns evaluation result.
```json
{"status": "ok", "data": {"event_type": "connect", "verdict": "allow", "directives": [...]}}
```

---

## Enterprise Admin

### `pilotctl audit [--network <network_id>]`
Retrieve the audit log for a network (default: backbone network 0). Requires `PILOT_ADMIN_TOKEN`.
```json
{"status": "ok", "data": {"entries": [{"timestamp": "RFC3339", "action": "node_registered", "node_id": 42, "network_id": 0, "details": "..."}]}}
```

### `pilotctl provision <blueprint.json>`
Provision a network from a JSON blueprint file. Creates the network with the specified configuration, RBAC roles, and policies. Requires `PILOT_ADMIN_TOKEN`.
```json
{"status": "ok", "data": {"network_id": 5, "name": "production", "actions": ["created network", "set join_rule=invite_only", "added 3 RBAC pre-assignments"]}}
```

### `pilotctl provision-status`
Show provisioning status: identity provider, audit export, webhook, and all provisioned networks. Requires `PILOT_ADMIN_TOKEN`.
```json
{"status": "ok", "data": {"idp_type": "oidc", "audit_export": "splunk_hec", "webhook_enabled": true, "networks": [{"network_id": 5, "name": "production", "enterprise": true, "members": 42, "join_rule": "invite_only", "rbac_pre_assignments": 3}]}}
```

### `pilotctl idp <get|set>`
Get or set the identity provider configuration. Requires `PILOT_ADMIN_TOKEN`.

**Get:** `pilotctl idp get`
```json
{"status": "ok", "data": {"configured": true, "idp_type": "oidc", "url": "https://login.example.com", "issuer": "https://login.example.com", "client_id": "abc123", "tenant_id": ""}}
```

**Set:** `pilotctl idp set --type <oidc|saml|entra_id|ldap|webhook> --url <URL> [--issuer URL] [--client-id ID] [--tenant-id ID] [--domain D]`
```json
{"status": "ok", "data": {"status": "configured"}}
```

### `pilotctl audit-export <get|set|disable>`
Configure external audit log export. Requires `PILOT_ADMIN_TOKEN`.

**Get:** `pilotctl audit-export get`
```json
{"status": "ok", "data": {"enabled": true, "format": "splunk_hec", "endpoint": "https://splunk.example.com:8088", "exported": 1042, "dropped": 0}}
```

**Set:** `pilotctl audit-export set --format <json|splunk_hec|syslog_cef> --endpoint <URL> [--splunk-token T] [--index I] [--source S]`
```json
{"status": "ok", "data": {"status": "configured"}}
```

**Disable:** `pilotctl audit-export disable`

### `pilotctl directory-sync <directory.json> [--network <id>] [--remove-unlisted]`
Sync a directory of node-to-identity mappings into a network. The JSON file contains `entries` (array of mappings) and optionally `network_id`. Use `--remove-unlisted` to disable nodes not in the file. Requires `PILOT_ADMIN_TOKEN`.
```json
{"status": "ok", "data": {"mapped": 50, "updated": 12, "disabled": 3, "unmapped": 0, "actions": ["mapped user@example.com → node 42"]}}
```

### `pilotctl directory-status <network_id>`
Show directory sync status for a network: total members, mapped/unmapped counts, pre-assignments, and last sync time. Requires `PILOT_ADMIN_TOKEN`.
```json
{"status": "ok", "data": {"network_id": 5, "total": 50, "mapped": 48, "unmapped": 2, "pre_assignments": 3, "last_sync": "2025-01-15T10:30:00Z"}}
```

---

## Diagnostics

### `pilotctl info`
```json
{
    "status": "ok",
    "data": {
        "node_id": 11,
        "address": "0:0000.0000.000B",
        "hostname": "mynode",
        "uptime_secs": 3600,
        "connections": 5,
        "ports": 3,
        "peers": 8,
        "encrypt": true,
        "encrypted_peers": 7,
        "authenticated_peers": 6,
        "bytes_sent": 1048576,
        "bytes_recv": 1048576,
        "pkts_sent": 1024,
        "pkts_recv": 1024,
        "identity": true,
        "public_key": "<hex-ed25519>",
        "email": "user@example.com",
        "conn_list": [...],
        "peer_list": [...]
    }
}
```

### `pilotctl health`
Lightweight health check. Returns daemon status, uptime, and resource usage.
```json
{"status": "ok", "data": {"status": "healthy", "uptime_seconds": 3600, "connections": 5, "peers": 8, "bytes_sent": 1048576, "bytes_recv": 1048576}}
```

### `pilotctl peers [--search <query>]`
```json
{"status": "ok", "data": {"peers": [{"node_id": 11, "endpoint": "1.2.3.4:12345", "encrypted": true, "authenticated": true}], "total": 1}}
```

### `pilotctl connections`
```json
{
    "status": "ok",
    "data": {
        "connections": [{
            "id": 1,
            "local_port": 1000,
            "remote_addr": "0:0000.0000.000B",
            "remote_port": 1000,
            "state": "established",
            "cwnd": 65536,
            "in_flight": 4096,
            "srtt_ms": 5.2,
            "unacked": 1,
            "ooo_buf": 0,
            "peer_recv_win": 131072,
            "recv_win": 131072,
            "bytes_sent": 102400,
            "bytes_recv": 102400,
            "segs_sent": 25,
            "segs_recv": 25,
            "retransmits": 0,
            "fast_retx": 0,
            "sack_recv": 0,
            "sack_sent": 0,
            "dup_acks": 0
        }],
        "total": 1
    }
}
```

### `pilotctl disconnect <conn_id>`
```json
{"status": "ok", "data": {"conn_id": 1}}
```

### `pilotctl ping <addr|hostname>`
**Flags:** `--count` (default 4), `--timeout` (default 30s)
```json
{"status": "ok", "data": {"target": "0:0000.0000.000B", "results": [{"seq": 0, "rtt_ms": 5.2, "bytes": 7}], "timeout": false}}
```
Sends "ping-{seq}" to port 7 (PortEcho), measures RTT.

### `pilotctl traceroute <address>`
**Flags:** `--timeout`
```json
{"status": "ok", "data": {"target": "...", "setup_ms": 15.5, "rtt_samples": [{"rtt_ms": 5.1, "bytes": 6}]}}
```

### `pilotctl bench <addr|hostname> [size_mb]`
**Default:** 1 MB, timeout 120s, sends 4096-byte chunks to port 7.
```json
{"status": "ok", "data": {"target": "...", "sent_bytes": 1048576, "recv_bytes": 1048576, "send_duration_ms": 100.5, "total_duration_ms": 205.3, "send_mbps": 9.95, "total_mbps": 4.87}}
```

### `pilotctl listen <port>`
**Flags:** `--count`, `--timeout`

NDJSON streaming: `{"src_addr": "...", "src_port": 1000, "data": "hello", "bytes": 5}`

### `pilotctl broadcast <network_id> <message>`
Not yet available — returns `unavailable` error code.

---

## Gateway Commands

### `pilotctl gateway start`
**Flags:** `--subnet` (default 10.4.0.0/16), `--ports`, `<pilot-addr>...`
```json
{"status": "ok", "data": {"pid": 54321, "subnet": "10.4.0.0/16", "mappings": [{"local_ip": "10.4.0.1", "pilot_addr": "0:0000.0000.000B"}]}}
```
Auto-creates loopback aliases. Writes PID to `~/.pilot/gateway.pid`. Requires root for ports <1024 on Linux.

### `pilotctl gateway stop`
```json
{"status": "ok", "data": {"pid": 54321}}
```

### `pilotctl gateway map <pilot-addr> [local-ip]`
```json
{"status": "ok", "data": {"local_ip": "10.4.0.1", "pilot_addr": "0:0000.0000.000B"}}
```

### `pilotctl gateway unmap <local-ip>`
```json
{"status": "ok", "data": {"unmapped": "10.4.0.1"}}
```

### `pilotctl gateway list`
```json
{"status": "ok", "data": {"mappings": [{"local_ip": "10.4.0.1", "pilot_addr": "0:0000.0000.000B"}], "total": 1}}
```

---

## Mailbox

### `pilotctl received [--clear]`
```json
{"status": "ok", "data": {"files": [{"name": "doc.pdf", "bytes": 102400, "modified": "RFC3339", "path": "~/.pilot/received/doc.pdf"}], "total": 1, "dir": "~/.pilot/received"}}
```

### `pilotctl inbox [--clear]`
```json
{"status": "ok", "data": {"messages": [{"type": "text", "from": "0:0000.0000.000A", "data": "hello", "received_at": "RFC3339"}], "total": 1, "dir": "~/.pilot/inbox"}}
```
