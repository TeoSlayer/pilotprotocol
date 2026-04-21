# Pilot Protocol — Problem Registry

Comprehensive catalog of edge cases, bugs, and reliability gaps that affect
agent-to-agent communication. Each entry includes root cause, exact code paths,
impact assessment, and fix strategy.

Last updated after full audit of daemon, tunnel, beacon, IPC, and service layers.

---

## Severity Levels

| Level | Meaning |
|-------|---------|
| **P0** | Silent data loss or indefinite hang — agents lose communication |
| **P1** | Degraded reliability or bounded hang (seconds to minutes) |
| **P2** | Performance degradation, DoS vector, or resource leak |
| **P3** | Theoretical, minor, or cosmetic |

---

## P0-001: FIN Before Data Reassembly — Silent Data Loss

**Status:** Fixed
**Files:** `daemon.go:1584-1625`, `ports.go:762-765, 847-857`

### Problem

When FIN arrives out-of-order (before all data segments), `CloseRecvBuf()` is
called immediately at line 1587, destroying the receive path. Any data segments
that arrive after FIN are silently dropped.

### Root Cause

FIN handler at daemon.go:1584 does three things wrong:
1. Calls `conn.CloseRecvBuf()` immediately (line 1587) — closes channel
2. Sets state to `StateTimeWait` (line 1591) — data handler at line 1673 checks
   `conn.State == StateEstablished` and rejects non-ESTABLISHED packets
3. Sends FIN-ACK with `Ack: pkt.Seq + 1` (line 1620) — tells sender "got everything"
   even if there's a gap

No `FinSeq` field exists on Connection to track where data ends.

### Failure Trace

```
Sender: segments [1000-2000], [2000-3000], FIN seq=3000
Receiver sees (reordered): FIN, [2000-3000], [1000-2000]

Step 1: FIN arrives → CloseRecvBuf() → RecvClosed=true, state=TimeWait
Step 2: [2000-3000] arrives → line 1673: state != Established → return (DROPPED)
Step 3: [1000-2000] arrives → same → return (DROPPED)
Result: 2000 bytes permanently lost, sender thinks delivery succeeded
```

### Also Affected

- FIN between in-order segments: [1000-2000] delivered, FIN closes RecvBuf,
  [2000-3000] dropped
- OOO segments in buffer when FIN arrives: segments stuck in OOOBuf forever
  (memory leak + data loss)
- DeliverInOrder early return at ports.go:762 — if RecvClosed, returns without
  checking if data should still be delivered

### Fix Strategy

1. Add `FinSeq uint32` and `FinReceived bool` fields to Connection
2. FIN handler: store FinSeq, do NOT call CloseRecvBuf
3. FIN handler: send FIN-ACK with `Ack: conn.ExpectedSeq` (not pkt.Seq+1)
4. Allow data packets in TimeWait state (modify line 1673 check)
5. DeliverInOrder: after advancing ExpectedSeq, check if `ExpectedSeq >= FinSeq`
   and only then close RecvBuf
6. CloseRecvBuf still uses sync.Once, so multiple trigger paths are safe

---

## P0-002: Key Exchange No Retry — Tunnel Stall

**Status:** Fixed
**Files:** `tunnel.go:757-778, 885-920`

### Problem

`sendKeyExchangeToNode()` fires exactly once over unreliable UDP. If the
PILA/PILK frame is lost, no retry mechanism exists. Packets queue in `pending`
map (max 64 per peer) indefinitely. The tunnel never establishes.

### Root Cause

- `sendKeyExchangeToNode()` at line 757-778: sends one frame, logs error on
  failure, never retries
- `Send()` at line 903: calls `sendKeyExchangeToNode()` then queues packet in
  `pending[nodeID]`, returns nil (success)
- No background retry loop, no timeout on pending queue
- Caller gets nil error and believes packet will be delivered

### Failure Trace

```
Node A calls Send(B, pkt):
  → sendKeyExchangeToNode(B) sends PILA over UDP → LOST
  → pkt queued in pending[B]
  → returns nil (success to caller)

No retry timer. pending[B] accumulates up to 64 packets.
65th packet: oldest silently dropped (line 910-912, returns nil!)
All subsequent Send() calls queue and return nil.
Tunnel never establishes. Application unaware.
```

### Fix Strategy

1. Track `lastKeyExchangeTime` per peer in tunnel manager
2. Background goroutine: every 500ms, check pending peers where
   `time.Since(lastKeyExchangeTime) > backoff`
3. Exponential backoff: 500ms → 1s → 2s → 4s → 8s (cap)
4. After N failures (e.g., 5), clear pending queue and return error
5. Return error from `Send()` when pending queue drops packets (line 910-912)

---

## P0-003: Key Exchange Response Lost — Asymmetric Crypto

**Status:** Fixed
**Files:** `tunnel.go:477-566, 639-656`

### Problem

If Node B processes Node A's PILA and sends a response PILA back, but the
response is lost, B has `ready=true` while A has `ready=false`. B sends
encrypted packets that A drops (line 652-654: "encrypted packet but no key").
A's pending queue fills. One-way communication failure.

### Root Cause

- No ACK/confirmation in key exchange protocol — fire-and-forget
- `handleEncrypted()` at line 652-654: if `!pc.ready`, logs Warn and returns
  (drops packet silently)
- No mechanism to detect asymmetric state or trigger re-key

### Failure Trace

```
T0: A sends PILA_A to B
T1: B receives PILA_A → B.ready=true → B sends PILA_B back → LOST
T2: B sends encrypted data to A
T3: A: handleEncrypted() → pc==nil or !ready → Warn log → DROP
T4: A: pending[B] fills to 64, oldest dropped
Asymmetry persists until A's next Send() triggers sendKeyExchangeToNode()
```

### Fix Strategy

1. In `handleEncrypted()`, when `pc != nil && !pc.ready`: instead of dropping,
   trigger `sendKeyExchangeToNode(peerNodeID)` to re-initiate
2. Rate-limit re-key triggers (max once per second per peer)
3. Track `asymmetricDropCount` — after threshold, force full re-key

---

## P0-004: startRecvPusher Exits Silently — routeLoop Stall

**Status:** Fixed
**Files:** `ipc.go:947-966`

### Problem

When IPC client disconnects, `startRecvPusher` goroutine exits at line 956
after `ipcWrite()` fails. RecvBuf remains open with no consumer. routeLoop's
`DeliverInOrder()` blocks for 1s per segment trying to push to the full buffer.

### Root Cause

- Line 955: error logged at DEBUG level only
- Line 956: `return` — goroutine exits, no cleanup
- RecvBuf channel never closed (only `CloseRecvBuf()` does that)
- `handleClient` deferred cleanup eventually calls `CloseConnection()` →
  `CloseRecvBuf()`, but timing is racy

### Failure Trace

```
1. IPC client disconnects → ipcWrite fails with "broken pipe"
2. startRecvPusher logs DEBUG, returns at line 956
3. RecvBuf is OPEN, capacity 512 segments
4. routeLoop calls DeliverInOrder → sends to RecvBuf
5. After 512 segments, RecvBuf full → each delivery blocks 1s (ports.go:818)
6. routeLoop stalls — ALL inbound packets for ALL connections delayed
7. Eventually handleClient cleanup fires → CloseRecvBuf()
```

### Fix Strategy

1. On `ipcWrite` error in RecvPusher, call `s.daemon.CloseConnection(c)` to
   trigger immediate RecvBuf close and FIN
2. Upgrade log level from Debug to Error
3. Consider: set a `conn.DriverDisconnected` flag so DeliverInOrder can
   short-circuit instead of blocking

---

## P0-005: readLoop Exits on Transient UDP Error — Silent Tunnel Death

**Status:** Fixed
**Files:** `tunnel.go:390-404`

### Problem

`readLoop()` exits on ANY `ReadFromUDP` error except "use of closed network
connection". Transient errors (EAGAIN, EINTR, ECONNREFUSED, temporary network
flicker) kill the tunnel permanently. Daemon continues running but cannot
receive any packets.

### Root Cause

Line 398-404: only checks one specific error string, otherwise returns:
```go
if err != nil {
    if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
        slog.Debug(...)
    } else {
        slog.Error("tunnel read error", ...)
    }
    return  // EXITS ON ANY ERROR
}
```

### Failure Trace

```
1. Transient network error (e.g., EINTR from signal, brief NIC flap)
2. ReadFromUDP returns error
3. Not "use of closed network connection" → slog.Error
4. readLoop returns at line 404
5. readWg.Done() fires
6. No new packets processed — tunnel is dead
7. Daemon still running, still attempting to Send() — packets queue
8. Connections timeout via keepalive (180s) but no recovery
```

### Fix Strategy

1. Use `net.Error` interface: check `Temporary()` and `Timeout()` for retryable errors
2. On transient error: log Warn, sleep with jittered exponential backoff
   (10ms→20ms→40ms... cap 1s), continue loop
3. Track consecutive transient errors — exit after threshold (e.g., 100)
4. On fatal error: log Error, return (current behavior)
5. Add `defer func() { recover() }()` for panic protection

---

## P0-006: sendSegment Blocks Forever on Zero Window

**Status:** Fixed
**Files:** `daemon.go:2064-2117`, `ports.go:528-537, 651-657`

### Problem

When peer advertises Window=0, `sendSegment()` enters an infinite select loop
probing every 30s with no maximum attempt count. The caller's goroutine is
blocked indefinitely. No timeout, no error returned to application.

### Root Cause

- sendSegment loop (line 2078-2116): only exits on `WindowCh` signal or
  `RetxStop` close
- Zero-window probes cap at 30s interval (ZeroWinProbeMax) but never give up
- `WindowCh` signaling is non-blocking (ports.go:654 `default` clause) — can
  drop signals
- No maximum probe count or total wait timeout

### Failure Trace

```
1. Peer's RecvBuf full → advertises Window=0 in ACK
2. sendSegment: WindowAvailable()=false → enter select loop
3. probeTimer fires every 500ms→1s→...→30s
4. Each probe sends ACK with our window; peer still at 0
5. Goroutine blocked at line 2078 select forever
6. Application's Send() call never returns
7. If peer dies, keepalive detects in 180s → RST → RetxStop closes
8. sendSegment finally exits (up to 3 minutes of hang)
```

### Fix Strategy

1. Add `MaxZeroWindowProbes = 20` constant (total ~5 min at 30s max)
2. After max probes, return `ErrWindowTimeout` error
3. Alternatively: add total timeout (e.g., 60s) via `time.After` in select
4. Signal WindowCh reliably: use `sync.Cond` instead of non-blocking channel

---

## P0-007: Stale Endpoint After NAT Rebind — Silent Packet Loss

**Status:** Fixed
**Files:** `tunnel.go:294-324, 544-545, 639-697`

### Problem

Peer endpoint (`tm.peers[nodeID]`) is only updated during key exchange
(tunnel.go:545). If peer's NAT rebinds (external IP:port changes),
`handleEncrypted()` receives packets from new IP but never updates the endpoint.
All outbound packets continue to the old (dead) address.

### Root Cause

- `handleEncrypted()` (line 639-697): decrypts packet from `from` parameter
  but never writes `from` to `tm.peers[nodeID]`
- `writeFrame()` (line 318): reads stale `tm.peers[nodeID]`
- `ensureTunnel()` (line 2514): if `HasPeer()` returns true, skips re-resolve
- Only endpoint update paths: `handleAuthKeyExchange()` line 545,
  `handleKeyExchange()` line 617, `AddPeer()` line 932

### Failure Trace

```
1. Connection established: peer at 1.2.3.4:4000 → tm.peers[B] = 1.2.3.4:4000
2. Peer's NAT rebinds → new external addr 5.6.7.8:4000
3. Peer sends encrypted packet from 5.6.7.8:4000
4. handleEncrypted(): decrypts OK, routes to routeLoop
5. Response: Send(B, ack) → writeFrame → tm.peers[B] = 1.2.3.4 (STALE)
6. Packet sent to dead address → dropped by NAT
7. Peer never gets ACK → retransmits → we receive again from 5.6.7.8
8. Loop: can receive, cannot send. One-way failure.
9. Persists until key exchange re-triggers (could be hours)
```

### Fix Strategy

1. In `handleEncrypted()`, after successful decryption: compare `from` with
   `tm.peers[peerNodeID]` — if different, update
2. Security: safe because only successfully decrypted packets trigger update
   (attacker without key cannot spoof)
3. Add rate-limit on endpoint updates (max 1 per second per peer) to prevent
   flip-flopping
4. Log endpoint changes at Info level for visibility

---

## P1-001: Retransmitted SYN Uses Wrong Sequence for SYN-ACK

**Status:** Open
**Files:** `daemon.go:1399-1420`

### Problem

When a retransmitted SYN arrives for an existing connection, the code resends
SYN-ACK with `Seq: eSeq - 1` (line 1414). If data has been sent on the
connection (advancing SendSeq), `eSeq - 1` is no longer the original SYN-ACK
sequence number.

### Impact

Handshake failure on retransmitted SYN after data flow has started.
Low frequency but can cause connection establishment to fail on lossy networks.

---

## P1-002: retxLoop Has No Panic Recovery

**Status:** Open
**Files:** `daemon.go:2170-2196`

### Problem

If `retxLoop` panics (e.g., nil pointer on tunnel Send, bad state), the
goroutine dies silently. No more retransmissions occur for that connection.
Connection stuck in StateFinWait or StateEstablished until idle sweep (135s).

### Fix Strategy

Add `defer func() { if r := recover(); r != nil { slog.Error(...) } }()` at
top of retxLoop. On panic, RST the connection and clean up.

---

## P1-003: Delayed ACK Timer Not Stopped on Close

**Status:** Open
**Files:** `daemon.go:2321-2349`

### Problem

`CloseConnection()` does not stop `conn.ACKTimer`. Timer fires after close,
sends ACK for dead connection. Wasted packet and unclean shutdown.

### Fix Strategy

In CloseConnection, after line 2345:
```go
conn.AckMu.Lock()
if conn.ACKTimer != nil { conn.ACKTimer.Stop(); conn.ACKTimer = nil }
conn.AckMu.Unlock()
```

---

## P1-004: Zero-Window Probing Has No Maximum Attempts

**Status:** Open
**Files:** `daemon.go:2078-2117`

### Problem

Zero-window probes continue every 30s indefinitely with no upper bound.
Resource leak: goroutine, timer, and probe packets consumed forever.

### Fix Strategy

Add `MaxZeroWindowProbes` constant. After exceeded, return error or RST.

---

## P1-005: Heartbeat Failure → Beacon Expiry Cascade

**Status:** Open
**Files:** `daemon.go:2600-2640`, `beacon/server.go:488`

### Problem

After 3 heartbeat failures, daemon enters re-register retry loop with
exponential backoff (max 30s). Beacon entry expires after 10 minutes of no
refresh (beaconNodeTTL). New peers cannot discover this node via beacon.

Circular dependency: registry down → no heartbeat → beacon entry expires →
can't discover via beacon → can't dial → isolated.

### Impact

Node isolation after ~10 minutes of registry unavailability.
Existing tunneled connections unaffected but new connections impossible.

---

## P1-006: Beacon Relay Drops Silent Under Load

**Status:** Open
**Files:** `beacon/server.go:324-337`

### Problem

128K relay queue. When full, packets dropped with rate-limited Warn log.
No backpressure to sender. No error returned via relay protocol.

### Impact

Under high relay load, connections degrade silently. Sender retransmits
but may hit MaxRetxAttempts and RST.

---

## P1-007: Replay Bitmap TOCTOU Race

**Status:** Open
**Files:** `tunnel.go:659-681`

### Problem

`checkAndRecordNonce()` runs under lock (line 659-668), records nonce bit.
Lock released before decrypt (line 668). If decrypt fails, lock re-acquired
to undo recording (line 678-681). Between release and re-acquire, concurrent
packet with same nonce could pass the check.

### Impact

Theoretical replay attack window. Requires exact timing and attacker control
of packet delivery. Low practical risk.

---

## P1-008: Pending Queue Overflow Drops Oldest Silently

**Status:** Open
**Files:** `tunnel.go:910-912`

### Problem

When pending queue per peer exceeds 64 packets, oldest dropped. `Send()`
returns `nil` (no error). Caller unaware of loss.

### Fix Strategy

Return error instead of nil when dropping. Or log at Warn level.

---

## P1-009: Task-Result Lost Across Peer Restart (Rekey Window Race)

**Status:** Open
**Files:** `cmd/pilotctl/main.go:2885-2998` (cmdTaskSendResults),
`pkg/tasksubmit/client.go` (SendResults), `pkg/daemon/tunnel.go` (rekey path).

### Problem

Scenario reproduced by `tests/integration/test_task_accepted_restart_recovery.sh`
without its warm-up ping: agent-a submits T1 to agent-b, b accepts (state on-disk),
then b restarts in place (identity.json preserved). After restart, b's worker calls
`pilotctl task send-results --id T1`. Locally, `cmdTaskSendResults` transitions
the task to SUCCEEDED on disk *before* the wire frames go out
(services.go:UpdateTaskFileWithTimes at line ~2947, then client.SendResults +
client.SendStatusUpdate fire-and-forget WriteFrame). The first outgoing
tasksubmit frame after the restart is silently dropped during the tunnel
rekey window (b has no crypto for a yet; key-exchange is initiated and the
frame is queued — but the VirtualConn layer above experiences handshake
turbulence when a still holds a stale Connection object for the old b).
The submitter never receives the result frame, so it stays at ACCEPTED
forever. Meanwhile b has no retry path because local state already reads
SUCCEEDED and the worker loop's filter (`status == "NEW" or "ACCEPTED"`)
no longer matches.

### Symptoms

- test_task_accepted_restart_recovery.sh without warm-up: submitter stays
  ACCEPTED, result text never lands.
- Adding `pilotctl ping agent-a` before the first send-results is enough to
  re-key the tunnel cleanly — all subsequent frames flow. This is the
  workaround currently baked into the test.

### Fix Strategy

Two independent layers help:

1. **cmdTaskSendResults state ordering:** don't flip local status to SUCCEEDED
   until we've confirmed the peer received the result. Options:
   (a) add an ack frame from receiver back to sender and await it with a
   short deadline, (b) leave status at ACCEPTED and let submitter-initiated
   status pushback drive the sender's local flip, or (c) accept eventual
   consistency but make send-results idempotent + retry until acked.
2. **Tunnel VirtualConn reset on peer rekey:** when `keyChanged == true` fires
   on either side (tunnel.go:617 / :697), proactively tear down any cached
   VirtualConns to that peer so higher layers redial cleanly instead of
   writing into a zombie connection.

Either fix alone probably closes the gap; both together is belt-and-braces.

---

## P2-001: connAdapter.SetReadDeadline Is No-Op

**Status:** Open (known issue)
**Files:** `services.go:85`

### Problem

Services relying on `SetReadDeadline()` (e.g., HTTP timeouts over Pilot)
get no actual timeout. Read blocks indefinitely on slow/dead senders.

### Impact

Service goroutine leaks. Connection slots consumed forever.

---

## P2-002: No Per-Client IPC Connection Quota

**Status:** Open
**Files:** `ipc.go:295-322`

### Problem

Single IPC client can dial unlimited connections, exhausting all 65536 slots.
No rate limiting or per-client quota.

### Impact

DoS by single rogue or buggy IPC client.

---

## P2-003: EventBroker Holds RLock During I/O

**Status:** Open
**Files:** `services.go:370-401`

### Problem

`publish()` holds `RLock` while iterating subscribers and calling
`WriteEvent()` for each. Slow subscriber blocks all publishers and other
subscribers.

### Fix Strategy

Collect subscribers under lock, release lock, then write outside lock.
Collect dead subscribers for later cleanup.

---

## P2-004: Datagram Broadcast Serialized to All IPC Clients

**Status:** Open
**Files:** `ipc.go:997-1001`

### Problem

`DeliverDatagram()` writes to each IPC client sequentially. Slow client
blocks routeLoop, stalling all inbound packet processing.

### Fix Strategy

Write to clients concurrently (goroutine per client) or use non-blocking
writes with error collection.

---

## P2-005: Nagle + Delayed ACK Silly Window Syndrome

**Status:** Open
**Files:** `daemon.go:1973-2042`

### Problem

1-byte writes with Nagle enabled: 40ms timeout per flush. If peer also has
40ms delayed ACK timer, throughput degrades to ~25 bytes/sec.

No Silly Window Syndrome avoidance on receiver side.

### Impact

Near-zero throughput for interactive/small-write patterns.

---

## P2-006: Stale Resolve Cache with NAT Rebind

**Status:** Open
**Files:** `daemon.go:2518-2541`

### Problem

Resolve cache has 60s TTL. Endpoint cache has 5-minute TTL as fallback.
Once `HasPeer()` returns true, `ensureTunnel()` skips re-resolve entirely.
If peer's IP changed, stale endpoint used until connection fails and triggers
full re-resolve.

---

## P2-007: DataExchange Partial File Not Cleaned Up

**Status:** Open
**Files:** `services.go:209-238`

### Problem

Interrupted file transfer leaves partial files on disk. No cleanup in error
path. Repeated failures accumulate disk usage.

---

## P2-008: Simultaneous Open Creates Duplicate Connections

**Status:** Open
**Files:** `daemon.go:1391-1420`

### Problem

Both sides dial each other simultaneously. Each receives SYN, creates passive
connection, sends SYN-ACK. Could result in two connections for same 4-tuple.

### Impact

Low frequency. Port allocation check prevents same local port reuse, but
different ephemeral ports could create two logical connections between same
address pair.

---

## P2-009: RTO Has No Jitter

**Status:** Open
**Files:** `daemon.go:2257-2259`

### Problem

Retransmit timeout is deterministic. Under congestion, all connections
retransmit simultaneously, amplifying congestion.

### Fix Strategy

Add random jitter: `RTO * (1 + rand(0, 0.25))`.

---

## P2-010: Registry Reconnect Can Duplicate Writes

**Status:** Open
**Files:** `registry/client.go:141-155`

### Problem

If TCP connection drops after write but before reading response, `Send()`
reconnects and retries the same message. Registry may process it twice
(duplicate heartbeat, register, etc.).

### Fix Strategy

Add request-ID nonce for idempotency. Or make all operations truly idempotent
server-side.

---

## P2-011: No Network Permission Check on Managed Score

**Status:** Open
**Files:** `ipc.go:1013-1050`

### Problem

IPC client can submit reputation scores for any network ID without
permission check. Client that left Network 5 can still manipulate its
reputation scores.

---

## P3-001: Nonce Collision (2^-32 per event)

**Files:** `tunnel.go:748`
4-byte random nonce prefix has birthday-bound collision probability.
Extremely unlikely per-connection, but non-zero across all connections.

## P3-002: Replay Window Too Small for Satellite Links

**Files:** `tunnel.go:76-78`
256-nonce sliding window rejects packets delayed >256 in sequence.
Insufficient for high-latency/high-jitter links (satellite, cellular).

## P3-003: AAD Missing Nonce in AEAD

**Files:** `tunnel.go:671`
Nonce not included in Additional Authenticated Data. GCM authenticates
nonce implicitly via tag, but defense-in-depth suggests including it.

## P3-004: Unauthenticated Key Exchange Downgrade

**Files:** `tunnel.go:591-598`
Unregistered node can establish tunnel with PILK (unauthenticated) even
when peer expects authenticated exchange. Silent security downgrade.

## P3-005: HandlePunchCommand No Retry

**Files:** `tunnel.go:1025-1051`
3 UDP punch packets sent. If all 3 lost, NAT hole-punch fails silently.
Probability very low (~10^-6 at 1% loss).

## P3-006: Close() Potential Deadlock on recvCh

**Files:** `tunnel.go:370-381`
If routeLoop blocked on something other than recvCh read, Close() at
line 377 (readWg.Wait) could hang. Mitigated by H5 fix closing recvCh.

## P3-007: Multi-Beacon Stale Gossip

**Files:** `beacon/server.go:516-550`
Lost gossip sync causes peer beacon to have stale node list. Adds extra
hop for relay lookups but doesn't lose data.

## P3-008: Trust Check Silent Fail When Registry Down

**Files:** `daemon.go:1427-1429`
`CheckTrust` error silently ignored. Private node blocks all untrusted
traffic during registry outage. Intentional for security but can cause
unexpected connectivity loss.

## P3-009: Hardcoded Challenge Size (40 bytes)

**Files:** `tunnel.go:790-791`
Challenge format assumes fixed 4+4+32 bytes. Future protocol changes to
nodeID or key size require careful migration.

## P3-010: handleRelayDeliver No Sender Validation

**Files:** `tunnel.go:1054-1116`
Relay message srcNodeID extracted from payload without beacon-level
authentication. If attacker controls relay path, can poison endpoint cache.

---

## Fixed Issues

### FIXED-001: RecvBuf Sequence Leak (was P0)

**Status:** Fixed
**Files:** `ports.go:753-845`
**Fix:** Three-phase DeliverInOrder — collect without advancing ExpectedSeq,
deliver outside lock, re-acquire to commit only delivered segments.

### FIXED-002: FIN Before Data Reassembly (was P0-001)

**Status:** Fixed
**Files:** `ports.go` (FinSeq/FinReceived fields, DeliverInOrder), `daemon.go` (FIN handler, data state check)
**Fix:** FIN is a sequence number, not an event. Added `FinSeq`/`FinReceived` to Connection.
FIN handler stores the sequence instead of closing RecvBuf. DeliverInOrder closes
RecvBuf only when `ExpectedSeq >= FinSeq`. Data accepted in TimeWait/FinWait states.
FIN-ACK uses cumulative ACK (not `pkt.Seq+1`).

### FIXED-003: Key Exchange No Retry (was P0-002)

**Status:** Fixed
**Files:** `tunnel.go` (SendTo, lastKeyExchange map)
**Fix:** Track `lastKeyExchange` per peer. In SendTo, re-trigger key exchange when
packets are pending and >1s since last attempt. Single lost PILA no longer stalls forever.

### FIXED-004: Key Exchange Response Lost / Asymmetric Crypto (was P0-003)

**Status:** Fixed
**Files:** `tunnel.go` (handleEncrypted)
**Fix:** When receiving encrypted packet without key, re-initiate key exchange (rate-limited
to 1/sec per peer) instead of silently dropping. Breaks the asymmetric state deadlock.

### FIXED-005: RecvPusher Exits Silently (was P0-004)

**Status:** Fixed
**Files:** `ipc.go` (startRecvPusher)
**Fix:** On IPC write error, call `CloseConnection()` immediately to close RecvBuf and
send FIN, preventing routeLoop stall on full buffer. Log upgraded to Warn.

### FIXED-006: readLoop Exits on Transient Error (was P0-005)

**Status:** Fixed
**Files:** `tunnel.go` (readLoop)
**Fix:** Only exit readLoop on shutdown signal (`tm.done`) or socket closed. All other
errors log Warn and continue. Transient UDP errors no longer kill the tunnel.

### FIXED-007: sendSegment Blocks Forever (was P0-006)

**Status:** Fixed
**Files:** `daemon.go` (sendSegment, MaxZeroWindowWait)
**Fix:** Added 60-second total deadline to zero-window probe loop. Returns error instead
of blocking indefinitely when peer's window stays at 0.

### FIXED-008: Stale Endpoint After NAT Rebind (was P0-007)

**Status:** Fixed
**Files:** `tunnel.go` (handleEncrypted)
**Fix:** After successful decryption, update `peers[peerNodeID]` to the packet's source
address. Safe because only holders of the shared key can produce valid ciphertext.
Logs endpoint changes at Info level.

---

## Cross-Reference: Failure Scenarios

### Scenario: Peer crashes without FIN
- P1-005 (keepalive): detects in ~180s (3 × 60s probes)
- P0-006 (sendSegment): blocked sender hangs until RST
- P1-002 (retxLoop): if panic, connection stuck 135s

### Scenario: NAT rebind
- P0-007 (stale endpoint): outbound packets lost
- P2-006 (stale resolve): up to 5 min before re-resolve
- P0-002 (key exchange): if re-key needed, only 1 attempt

### Scenario: Network congestion
- P1-006 (relay drops): relay queue fills, packets lost
- P0-006 (zero window): sender hangs if peer window=0
- P2-005 (Nagle/SWS): throughput collapses for small writes
- P2-009 (no jitter): synchronized retransmits amplify congestion

### Scenario: IPC client crash
- P0-004 (RecvPusher): RecvBuf never drained, routeLoop stalls
- P0-001 (FIN ordering): if close races with data, segments lost

### Scenario: Registry unavailable
- P1-005 (beacon cascade): node isolated after 10 min
- P3-008 (trust check): private node blocks all new connections
- P2-010 (duplicate writes): retry may double-count operations

---

## End-to-End User Journey: Where Bugs Hit

The typical flow is: **install → start daemon → trust peer → send message**.
Below is the exact path through the code and which problems apply at each step.

### Phase 1: Install & Start Daemon

```
User: curl -fsSL https://pilotprotocol.network/install.sh | sh
User: pilotctl daemon start --email me@example.com
```

**What happens:**
1. pilotctl forks `_daemon-run` subprocess, polls `/tmp/pilot.sock` for readiness
2. Daemon opens temp UDP socket → STUN discover to beacon → learns public IP:port
3. Closes temp socket, binds tunnel on same port
4. Generates or loads Ed25519 identity from `~/.pilot/identity.json`
5. TCP connect to registry → `RegisterWithKey(pubkey, email, endpoint)` → gets `node_id`
6. Registers with beacon for NAT traversal
7. Starts: routeLoop, heartbeatLoop, idleSweepLoop, relayProbeLoop, IPC server
8. Binds built-in services: echo(7), dataexchange(1001), eventstream(1002), tasksubmit(1003)

**Bugs that apply here:**
- **P0-005** (readLoop exit): if a transient UDP error occurs during startup,
  the tunnel dies silently. Daemon reports "ready" but can't receive packets.
- **P1-005** (heartbeat cascade): if registry was briefly unreachable during
  registration, beacon entry may not be created. First heartbeat in 60s fixes it.

### Phase 2: Trust Establishment

```
Agent A: pilotctl handshake <B-node-id> "want to collaborate"
Agent B: pilotctl pending        → sees A's request
Agent B: pilotctl approve <A-node-id>
```

**What happens:**
1. A's daemon dials B's handshake port (444) — or relays via registry if B is private
2. Sends signed `handshake_request` JSON with justification
3. B's daemon stores in `~/.pilot/trust.json` pending list
4. On approval: B calls `registry.ReportTrust(B, A)`, sends `handshake_accept` to A
5. Both sides store trusted peer in `~/.pilot/trust.json`

**Bugs that apply here:**
- **P3-008** (trust check silent fail): if registry is down when B tries to
  verify A's identity, the handshake silently fails. User sees no error —
  just no handshake arrives.
- **P0-002** (key exchange no retry): the handshake message itself travels over
  a Pilot connection. If the tunnel key exchange to the handshake relay is lost
  (single UDP packet), the handshake is never delivered. User must manually retry.
- **P0-003** (asymmetric crypto): if key exchange response is lost, A can receive
  from B but not send to B. A's handshake request queues in pending, never arrives.

**What the user sees:** "handshake request sent" — then silence. No error if the
handshake was lost. User must check `pilotctl pending` on B and retry if empty.

### Phase 3: First Connection (Dial)

```
Agent A: pilotctl send <B-address> 7 --data "hello"
  → internally: driver.DialAddr(B, 7) → IPC CmdDial → daemon.DialConnection()
```

**What happens:**
1. Daemon resolves B's address via registry → gets B's UDP endpoint
2. Calls `ensureTunnel(B)` → AddPeer → `sendKeyExchangeToNode(B)` (PILA frame)
3. Waits for key exchange response (PILA back from B)
4. Encrypts SYN packet, sends via UDP tunnel
5. B receives SYN → checks trust gate → if trusted, sends SYN-ACK
6. A receives SYN-ACK → sends ACK → connection ESTABLISHED
7. A sends data segment "hello" → B's echo service receives → echoes back

**Bugs that apply on this path:**

| Step | Bug | What user sees |
|------|-----|---------------|
| 2 | **P0-002** (key exchange lost) | `dial: i/o timeout` after 30s. PILA was lost, tunnel never established. Retry works. |
| 2 | **P0-003** (asymmetric crypto) | Same timeout. B can see A but A can't reach B. |
| 3 | **P0-007** (stale endpoint) | If B's NAT rebind happened since last resolve, SYN goes to dead address. `dial: i/o timeout`. |
| 5 | **P3-008** (trust silent fail) | If registry down, B silently drops SYN. A sees `dial: i/o timeout` with no explanation. |
| 5 | **P1-001** (SYN retx wrong seq) | If A's SYN is lost and retransmitted after data sent, B sends SYN-ACK with wrong seq. Connection fails. |
| 6 | **P0-005** (readLoop exit) | If A's tunnel readLoop died from transient error, SYN-ACK never received. `dial: i/o timeout`. Daemon appears healthy. |

### Phase 4: Data Transfer

```
After connection is established:
  A: conn.Write([]byte("hello"))  →  daemon.SendData  →  tunnel  →  UDP
  B: echo service reads RecvBuf   →  echoes back        →  tunnel  →  UDP
  A: conn.Read(buf)               ←  RecvPusher pushes CmdRecv to driver
```

**Bugs that apply during active data transfer:**

| Bug | Trigger | What user sees |
|-----|---------|---------------|
| **P0-001** (FIN data loss) | B closes connection while A's last segments are in flight. UDP reorders FIN before data. | A's `conn.Read()` returns io.EOF but last few bytes of response are missing. **Silent data corruption.** |
| **FIXED-001** (RecvBuf seq leak) | RecvBuf was full for >1s. Now fixed — sender retransmits correctly. | *(Fixed)* Previously: silent byte loss. Now: ~1s stall then recovery. |
| **P0-004** (RecvPusher exit) | A's IPC client crashes/disconnects while data is flowing. | RecvBuf fills → routeLoop stalls for all connections → all inbound traffic delayed 1s per segment. Other connections on same daemon degraded. |
| **P0-006** (sendSegment block) | B's receive buffer full (slow reader). B advertises Window=0. | A's `conn.Write()` blocks forever. No timeout, no error. Application hangs. |
| **P0-007** (stale endpoint) | B's NAT rebinds mid-transfer. | A keeps sending to old IP. B sees timeout. A sees retransmit failures → RST after ~80s. Connection dies with "connection reset". |
| **P2-005** (Nagle/SWS) | A writes 1 byte at a time (e.g., interactive chat). | Throughput drops to ~25 bytes/sec. Messages arrive in bursts every 40ms. Feels extremely laggy. |
| **P1-006** (relay drops) | Connection is relayed through beacon under load. | Random packet loss → retransmissions → throughput drops. Under heavy load, connection may RST after MaxRetxAttempts. |

### Phase 5: Connection Close

```
A: conn.Close()  →  CmdClose  →  daemon sends FIN to B
B: receives FIN   →  sends FIN-ACK  →  connection enters TimeWait
```

**Bugs that apply during close:**

| Bug | Trigger | What user sees |
|-----|---------|---------------|
| **P0-001** (FIN data loss) | FIN arrives at B before B finishes delivering OOO segments to its application. | B's application reads partial data, then io.EOF. Bytes are permanently lost. |
| **P1-003** (ACK timer leak) | Connection closes while delayed ACK timer is pending. | Wasted ACK packet sent to closed peer. No user-visible effect but unclean. |

### Phase 6: Long-Running Agent (Hours/Days)

**Bugs that surface over time:**

| Bug | Trigger | What user sees |
|-----|---------|---------------|
| **P0-005** (readLoop exit) | Transient UDP error after hours of operation (e.g., NIC driver hiccup). | Agent suddenly unreachable. `pilotctl daemon status` shows "running" but all connections fail. Must restart daemon. |
| **P1-005** (heartbeat cascade) | Registry maintenance or brief outage >10min. | New peers can't discover this agent via beacon. Existing connections fine. Agent appears offline to new peers. |
| **P0-007** (stale endpoint) | Peer's external IP changes (mobile network, cloud VM migration). | Existing connections die with timeout. New dials to peer work (fresh resolve). |
| **P2-002** (no IPC quota) | Bug in SDK causes connection leak. | After 65536 connections, daemon refuses new dials. All IPC clients affected. |

### Summary: User Experience Quality by Phase

| Phase | Expected behavior | Actual reliability | Key risks |
|-------|-------------------|-------------------|-----------|
| Install & start | ~5s, always works | Good | P0-005 rare |
| Trust setup | Send request, peer approves, immediate | Fragile on lossy networks | P0-002/003: handshake lost silently |
| First dial | <1s connection | Usually works, flaky on NAT | P0-002: key exchange lost → 30s timeout |
| Data transfer | Reliable, ordered | Good for small data. Degrades under load/loss | P0-001: FIN ordering; P0-006: write hang |
| Long-running | Stays connected | Degrades over time | P0-005: tunnel dies; P1-005: beacon expires |

### The Critical Path

The single most common failure a user will hit:

**"I trusted Agent B, sent a message, and it timed out."**

Root cause chain:
1. `pilotctl send B 1001 --data "hello"` → driver calls `DialAddr(B, 1001)`
2. Daemon calls `ensureTunnel(B)` → resolves endpoint → `AddPeer(B, addr)`
3. `AddPeer` triggers `sendKeyExchangeToNode(B)` → sends **one PILA packet** over UDP
4. **PILA is lost** (0.1-1% probability on any network)
5. No retry mechanism (P0-002)
6. Data packet queued in `pending[B]` (max 64)
7. Daemon returns nil to driver (no error visible)
8. Driver's `DialAddr` blocks waiting for SYN-ACK that will never come
9. After 30s: `dial: i/o timeout`
10. User retries → this time PILA gets through → works

**User experience:** "It failed once, then worked. Flaky."

This is why **P0-002 (key exchange retry)** is the highest-impact fix for real
users — it eliminates the most common first-connection failure.
