# Pilot Protocol — Package Reference

## pkg/protocol — Core Wire Format

**Types:**
- `Addr` (6 bytes): 16-bit network + 32-bit node. Methods: `String()`, `ParseAddr()`, `Marshal()`, `UnmarshalAddr()`
- `SocketAddr`: virtual address + port. Methods: `ParseSocketAddr()`, `String()`
- `Packet` (34-byte header): Version, Flags, Protocol, PayloadLen, Src/Dst Addr, Src/Dst Port, Seq, Ack, Window, CRC32

**Constants:**
- Protocols: `ProtoStream(1)`, `ProtoDatagram(2)`, `ProtoControl(3)`
- Flags: `FlagSYN(0x1)`, `FlagACK(0x2)`, `FlagFIN(0x4)`, `FlagRST(0x8)`
- Well-known addresses: `AddrZero`, `AddrRegistry`, `AddrBeacon`, `AddrNameserver`
- Beacon messages: Discover(1), DiscoverReply(2), PunchRequest(3), PunchCommand(4), Relay(5), RelayDeliver(6), Sync(7)
- Error sentinels: `ErrNodeNotFound`, `ErrNetworkNotFound`, `ErrConnClosed`, `ErrConnRefused`, `ErrDialTimeout`, `ErrChecksumMismatch`

---

## pkg/driver — Client SDK (IPC over Unix Socket)

**Types:**
- `Driver`: Main entry point. Methods: `Connect()`, `Dial()`, `DialAddr()`, `Listen()`, `SendTo()`, `RecvFrom()`, `Info()`, `Health()`, `Handshake()`, `Approve/Reject()`, `Trust/Pending()`, `SetHostname()`, `SetTags()`, `SetWebhook()`, `SetVisibility()`, `SetTaskExec()`, `Deregister()`, `Disconnect()`, `NetworkList/Join/Leave/Members/Invite/PollInvites/RespondInvite()`, `ResolveHostname()`, `ManagedScore/Status/Rankings/ForceCycle()`, `PolicyGet/Set()`, `Close()`
- `Conn` (implements `net.Conn`): TCP-like streaming. Methods: `Read()`, `Write()`, `Close()`, `SetDeadline()`, `SetReadDeadline()`
- `Listener` (implements `net.Listener`): Port binding. Methods: `Accept()`, `Close()`
- `Datagram`: `SrcAddr`, `SrcPort`, `DstPort`, `Data`

**IPC Commands (internal):**
- Bind(0x01)/BindOK(0x02), Dial(0x03)/DialOK(0x04), Accept(0x05), Send(0x06)/Recv(0x07), Close(0x08)/CloseOK(0x09)
- Error(0x0A), SendTo(0x0B)/RecvFrom(0x0C), Info(0x0D)/InfoOK(0x0E)
- Handshake(0x0F)/HandshakeOK(0x10), ResolveHostname(0x11)/ResolveHostnameOK(0x12), SetHostname(0x13)/SetHostnameOK(0x14)
- SetVisibility(0x15)/SetVisibilityOK(0x16), Deregister(0x17)/DeregisterOK(0x18)
- SetTags(0x19)/SetTagsOK(0x1A), SetWebhook(0x1B)/SetWebhookOK(0x1C), SetTaskExec(0x1D)/SetTaskExecOK(0x1E)
- Network(0x1F)/NetworkOK(0x20), Health(0x21)/HealthOK(0x22)
- Network sub-commands: List(0x01), Join(0x02), Leave(0x03), Members(0x04), Invite(0x05), PollInvites(0x06), RespondInvite(0x07)
- Managed(0x23)/ManagedOK(0x24) — sub-commands: Score(0x01), Status(0x02), Rankings(0x03), Cycle(0x04), Policy(0x05)

---

## pkg/secure — Encryption Layer (Port 443)

**Types:**
- `SecureConn` (wraps `net.Conn`): AES-256-GCM with X25519 ECDH

**Functions:**
- `Handshake(conn, isServer)` → `*SecureConn`: 10s timeout, role-based nonce prefix (server=0x01, client=0x02)
- `HandshakeWithLookup(conn, isServer, lookupFn)` → `*SecureConn`: with cert verification callback
- `HandshakeWithTimestampOffset(conn, isServer, offset)` → `*SecureConn`: with clock offset tolerance
- Wire: `[4-byte length][12-byte nonce][ciphertext + GCM tag]`
- Key derivation: HKDF-SHA256 (Extract+Expand with info "pilot-secure-v1")
- GCM AAD: sender's nonce prefix (first 4 bytes of nonce)
- Replay protection: nonce cache (100K entries max)
- Max message: 16 MB

---

## pkg/registry — Node Registry Server

**Types:**
- `Server`: TCP listener, manages nodes/networks/hostnames/trust
  - Indices: nodes, pubKeyIdx, ownerIdx, hostnameIdx
  - Persistence: debounced JSON snapshots
  - Replication: push-based snapshots, 15s heartbeat
  - TLS support, admin token validation (constant-time compare)
  - Enterprise: RBAC (owner/admin/member), network policies, audit trail
  - Signature verification: Ed25519 signed operations, admin token fallback for keyless nodes
  - Handshake relay: forwards trust handshakes between private nodes
- `Client`: TCP/TLS with auto-reconnect, cert pinning, signed operations, mutex-protected Send()

---

## pkg/beacon — NAT Traversal

**Types:**
- `Server`: UDP listener, tracks node endpoints
  - Relay workers: 1 per CPU core, 4096-entry queue
  - Gossip: beacon-to-beacon MsgSync
  - Buffer pool: 1500-byte reusable buffers

**Functions:**
- `New()`, `NewWithPeers(beaconID, peers)`, `ListenAndServe(addr)`
- Relay format: `[0x05][senderNodeID(4)][destNodeID(4)][payload...]`

---

## pkg/dataexchange — Typed Frame Protocol (Port 1001)

**Types:**
- `Frame`: Type + Payload + Filename. Types: Text(1), Binary(2), JSON(3), File(4)

**Functions:**
- `WriteFrame(w, f)`, `ReadFrame(r)`, `TypeName(t)`
- Wire: `[4-byte type][4-byte length][payload]`. File: `[2-byte name length][name][data]`
- Max payload: 16 MB

---

## pkg/eventstream — Pub/Sub (Port 1002)

**Types:**
- `Event`: Topic + Payload

**Functions:**
- `WriteEvent(w, e)`, `ReadEvent(r)`
- Wire: `[2-byte topic length][topic][4-byte payload length][payload]`
- Topic max: 1024 bytes, Payload max: 16 MB

---

## pkg/tasksubmit — Task Lifecycle (Port 1003)

**Types:**
- `SubmitRequest`: TaskID, TaskDescription, FromAddr, ToAddr
- `SubmitResponse`: TaskID, Status (200/400), Message
- `TaskFile`: Status (NEW→ACCEPTED→EXECUTING→SUCCEEDED), timestamps, durations
- `TaskResultMessage`: ResultType ("text"/"file"), time metadata
- `Frame`: TypeSubmit(1), TypeResult(2), TypeStatusUpdate(3), TypeSendResults(4)
- `PoloScoreBreakdown`: base, cpuBonus, idle/staged factors, efficiency multiplier

**Key Functions:**
- `GenerateTaskID()`, `NewTaskFile()`, `WriteFrame()`, `ReadFrame()`
- `PoloScoreReward()`, `PoloScoreRewardDetailed()`
- `IsExpiredForAccept()` (1 min), `IsExpiredInQueue()` (1 hour)

**Polo Score Formula:**
- base=1.0, cpuBonus=log2(1+cpu_min), idlePenalty=min(idle/60s, 0.3), stagedPenalty=min(staged/600s, 0.3)
- efficiency=1.0-idle-staged (min 0.4), final=round(base+cpuBonus)*efficiency (min 1)

**Allowed result extensions:** .md, .txt, .pdf, .csv, .jpg, .png, .svg, .pptx, .parquet, etc.
**Forbidden:** .go, .py, .js, .ts, .java, .c, .sh, .sql, etc. (no source code)

---

## pkg/policy — Network Policy Engine

**Types:**
- `EventType`: connect, dial, datagram, cycle, join, leave
- `ActionType`: allow, deny, score, tag, evict, evict_where, prune, fill, webhook, log
- `PolicyDocument`: Version + Rules + Settings (cycle_duration, max_peers, grace_period)
- `Rule`: Name, On (event), When (CEL expression), Actions
- `CompiledPolicy`: compiled rules with CEL programs

**Functions:**
- `Parse(json)` → `*PolicyDocument`: parse and validate policy JSON
- `Compile(doc)` → `*CompiledPolicy`: compile CEL expressions
- `Evaluate(eventType, ctx)` → `[]Directive`: run policy against an event
- `EvaluatePeerExpr()`: evaluate per-peer expressions (e.g., evict_where)
- `HasRulesFor(eventType)`: check if policy handles an event type
- `CycleDuration()`, `MaxPeers()`: query policy settings

---

## pkg/console — Admin Web Console

**Types:**
- `Server`: HTTP server with auth, rate limiting, CORS, Stripe billing
- `Config`: ListenAddr, RegistryAddr, AdminToken, DatabasePath, StripeKey, etc.

**Handlers:** auth, admin, billing, enterprise, keys, networks, nodes

---

## pkg/gateway — IP Bridge

**Types:**
- `Gateway`: Maps pilot addresses to local IPs, proxies TCP through tunnel
- `Config`: Subnet (10.4.0.0/16), SocketPath, Ports

**Functions:**
- `New(cfg)`, `Start()`, `Stop()` (idempotent, cleans up loopback aliases)

---

## pkg/nameserver — DNS-like Discovery (WIP)

**Types:**
- `Server`: Port 53, backed by RecordStore
- `RecordStore`: A/N/S records, 5-min TTL, background reaper

**Wire protocol (text, newline-delimited):**
- `QUERY A|N|S <name>`, `REGISTER A|N|S <name> <addr> [net_id] [port]`

---

## pkg/config — Configuration

- `Load(path)` → `map[string]interface{}`
- `ApplyToFlags(cfg)` — merges JSON into flag defaults

---

## pkg/logging — Structured Logging

- `Setup(level, format)` — configure slog. Levels: debug/info/warn/error. Formats: text/json

---

## internal/crypto — Identity Management

- `Identity`: Ed25519 PublicKey + PrivateKey
- `GenerateIdentity()`, `Sign()`, `Verify()`, `Encode/DecodePublicKey()`, `Save/LoadIdentity()`
- Persisted as JSON (mode 0600)

## internal/ipcutil — IPC Serialization

- `Read(r)`, `Write(w, data)` — 4-byte big-endian length-prefixed messages
- `MaxMessageSize = 1MB`

## internal/fsutil — File Utilities

- `AtomicWrite(path, data)` — write to temp, fsync, rename

## internal/pool — Buffer Pools

- `SmallBufSize = 4096` (IPC), `LargeBufSize = 65573` (tunnel)
- `GetSmall()/PutSmall()`, `GetLarge()/PutLarge()`

## internal/account — Account Persistence

- `Account`: Email field, persisted as JSON (mode 0600)
- `Save(path, acct)`, `Load(path)`, `PathFromIdentity(identityPath)`

## internal/validate — Input Validation

- `Email(email)` — basic email validation (non-empty, single @, domain has dot, no spaces)
