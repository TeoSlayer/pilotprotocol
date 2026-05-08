# Pilot Protocol — Architecture & Data Pathways

Mermaid diagrams + component reference, grouped by concern. Each section introduces the component, shows its pathway, and lists the files, state, and invariants so two sibling components can be compared without hunting.

---

## 1 · Conceptual model

Pilot layers three planes over raw UDP:

- **Addressing plane** — stable 48-bit identifier (16-bit network + 32-bit node). IP:port can change as NAT mappings expire; the Pilot address cannot.
- **Control plane** — Rendezvous (registry TCP + beacon UDP, optionally replicated) holds the directory, trust pairs, and orchestrates NAT traversal. Authoritative for the `nodeID ↔ Ed25519 pubkey` binding.
- **Data plane** — TCP-like semantics (SYN/ACK/FIN, cwnd, SACK, three-phase reassembly) implemented in user space inside the daemon, carried over UDP with a 34-byte header. Optionally AES-GCM wrapped.

Applications never touch UDP. They speak IPC to a local daemon; the daemon owns the socket, the crypto, the FSM, and the traversal decisions. That's why an SDK in any language can interoperate without re-implementing the wire protocol.

---

## 2 · Primitives

### 2.1 Address — `pkg/protocol/address.go`
48-bit value: `NetworkID u16 | NodeID u32`, big-endian on the wire (6 bytes). Text form `N:NNNN.HHHH.LLLL`. Every packet carries both Src and Dst. `NetworkID` lets multiple logical networks coexist on the same rendezvous.

### 2.2 Packet header — `pkg/protocol/packet.go`

```mermaid
flowchart TB
  subgraph H[34-byte header]
    direction LR
    B0["byte 0<br/>ver:4 | flags:4"]
    B1["byte 1<br/>Protocol"]
    B23["bytes 2-3<br/>PayloadLen u16"]
    B49["bytes 4-9<br/>SrcAddr 48-bit"]
    BAF["bytes 10-15<br/>DstAddr 48-bit"]
    B1617["16-17<br/>SrcPort u16"]
    B1819["18-19<br/>DstPort u16"]
    B2023["20-23<br/>Seq u32"]
    B2427["24-27<br/>Ack u32"]
    B2829["28-29<br/>Window u16 segments"]
    B3033["30-33<br/>CRC32 checksum"]
    B0 --- B1 --- B23 --- B49 --- BAF --- B1617 --- B1819 --- B2023 --- B2427 --- B2829 --- B3033
  end
```

- **Flags** (byte 0 low nibble): `SYN=1 · ACK=2 · FIN=4 · RST=8`.
- **Protocol** (byte 1): `Stream=1 · Datagram=2 · Control=3`.
- **Checksum**: CRC32 over (header-with-zeroed-checksum) + payload.
- **Window** is in MSS-sized segments, not bytes.

### 2.3 Tunnel framing magic — `pkg/protocol/header.go`

First 4 bytes of every UDP payload; receiver dispatches on this tag before parsing the header:

| Magic | Hex | Meaning |
|---|---|---|
| PILT | `0x50494C54` | plaintext Pilot packet |
| PILS | `0x50494C53` | encrypted Pilot packet (AES-GCM → decrypts to a PILT frame) |
| PILK | `0x50494C4B` | ECDH key exchange |
| PILA | `0x50494C41` | authenticated key exchange |
| PILP | `0x50494C50` | NAT hole-punch (4B only, no header) |

### 2.4 Identity
Ed25519 keypair at `~/.pilot/identity.json`. Node ID is bound to the pubkey in the registry. All heartbeats carry an Ed25519 signature. Trust handshakes bind peer ID pairs + timestamps with a second Ed25519 sig to prevent cross-peer replay.

### 2.5 Flow control constants — `pkg/daemon/ports.go:102-118`

`MSS=4096 · InitialCongWin=40KB · InitialRTO=1s · RTOMin=200ms · RTOMax=10s · MaxOOOBuf=128 · ClockGranularity=10ms`.

---

## 3 · Process topology

```mermaid
graph LR
  App[Application<br/>net/http, pilotctl, SDKs]
  Drv[Driver<br/>pkg/driver/driver.go]
  GW[Gateway<br/>pkg/gateway/gateway.go]
  Upd[Updater<br/>cmd/updater]
  NS[Nameserver<br/>cmd/nameserver]

  subgraph Local[Local host]
    Drv -- unix /tmp/pilot.sock --> D
    GW -- unix /tmp/pilot.sock --> D
    App --> Drv
    D[(Daemon<br/>cmd/daemon)]
  end

  subgraph Rendezvous[Rendezvous cmd/rendezvous]
    R[Registry<br/>TCP :9000]
    B[Beacon<br/>UDP :9001]
    HTTP[Dashboard<br/>HTTP opt]
  end

  D -- TCP heartbeat/lookup --> R
  D -- UDP discover/punch/relay --> B
  D <-. UDP tunnel .-> D2[(Daemon peer)]
  D2 -. UDP .-> B
  D2 -. TCP .-> R
  Upd --> R
  NS --> R
```

**Daemon** (`cmd/daemon/main.go`) — listens UDP for tunnel, Unix socket for IPC. Reserved system ports: 7 (echo), 80/443 (HTTP/S), 444 (trust handshake), 1000 (stdio), 1001 (data exchange), 1002 (event stream).

**Rendezvous** (`cmd/rendezvous/main.go`) — single binary = registry + beacon + optional dashboard/standby. Flags: `-registry-addr :9000`, `-beacon-addr :9001`, `-http`, `-standby`, `-store`. Canonical GCP instance `34.71.57.205:9000/9001`.

**Pilotctl / SDKs / Gateway** — IPC clients. They never open UDP themselves, which is what makes them safe on hosts that shouldn't.

---

## 4 · Control plane

### 4.1 Registry — `pkg/registry/`

```mermaid
sequenceDiagram
  participant D as Daemon
  participant R as Registry (TCP :9000)
  Note over D,R: pkg/registry/client.go holds ConnMu<br/>serializes heartbeat & lookup on shared TCP

  D->>R: 0x01 Heartbeat (nodeID 4B + Ed25519 sig 64B)
  R-->>D: 0x81 time + keyExpiryFlag
  D->>R: 0x02 Lookup (nodeID 4B)
  R-->>D: 0x82 public, polo, nets, pubkey, host, tags, realAddr, externalID
  D->>R: 0x03 Resolve (nodeID 4B + requesterID 4B + sig 64B)
  R-->>D: 0x83 realAddr + LAN addrs + keyAgeDays
  Note over R: WAL append + periodic snapshot<br/>registry/wal.go
```

**Purpose.** Node directory, identity binding, trust pairs.
**Persistence.** WAL + periodic snapshot. Canonical path `/var/lib/pilot/registry.json` on the GCP rendezvous VM.
**Mutex.** Every op takes `ConnMu` so concurrent lookups don't interleave binary/JSON frames on the shared TCP socket.
**Files.** `server.go`, `client.go`, `wire.go` (message layouts at lines 136-233 lookup, 237-286 resolve), `wal.go`.

### 4.2 Beacon — `pkg/beacon/`

```mermaid
flowchart LR
  subgraph M[Beacon message types — protocol/header.go:76-85]
    m1[0x01 Discover]
    m2[0x02 DiscoverReply]
    m3[0x03 PunchRequest]
    m4[0x04 PunchCommand]
    m5[0x05 Relay]
    m6[0x06 RelayDeliver]
    m7[0x07 Sync]
  end
  A[Daemon] -- Discover --> B[(Beacon)]
  B -- DiscoverReply with observed IP:port --> A
  A -- heartbeat.realAddr --> R[(Registry)]
  B -. Sync peer list .- B2[(Peer beacon standby)]
```

Endpoint discovery is implicit STUN: the beacon observes `src IP:port` of the Discover datagram and echoes it back in DiscoverReply. The daemon stores it and publishes via registry heartbeat.

**Workers.** `runtime.NumCPU()*2` relay workers draining a 131K-slot queue (`beacon/server.go:128-134`).
**Node TTL.** 10 minutes.

### 4.3 NAT traversal

```mermaid
flowchart TD
  S[DialConnection<br/>daemon.go:2081-2181]
  S --> P[policy check]
  P --> T[ensureTunnel crypto]
  T --> K[send SYN]
  K --> W{ESTABLISHED<br/>within RTO?}
  W -- yes --> OK[return conn]
  W -- no --> D{directAttempts < 3?}
  D -- yes --> K
  D -- no --> B{beacon configured<br/>and not already relay?}
  B -- no --> F[ErrDialTimeout]
  B -- yes --> SR[SetRelayPeer true<br/>daemon.go:2157-2162]
  SR --> KR[send SYN via relay]
  KR --> WR{ESTABLISHED?}
  WR -- yes --> OK
  WR -- no --> RR{relayAttempts < 3?}
  RR -- yes --> KR
  RR -- no --> F
```

Retries: `DialDirectRetries=3`, `DialMaxRetries=6`. RTO: `DialInitialRTO=1s` initial, `DialMaxRTO=8s` max, exponential backoff; reset to initial when switching to relay (`daemon.go:2162`).

#### 4.3a Hole-punch sequence

```mermaid
sequenceDiagram
  participant A as Peer A
  participant B as Beacon
  participant C as Peer C

  A->>B: 0x03 PunchRequest (target=C)
  B->>A: 0x04 PunchCommand (peer=C ep)
  B->>C: 0x04 PunchCommand (peer=A ep)
  par simultaneous
    A->>C: 4-byte PILP punch packet
    C->>A: 4-byte PILP punch packet
  end
  Note over A,C: NAT mappings created on both sides
  A->>C: SYN (normal Pilot packet)
  C-->>A: SYN|ACK
```

#### 4.3b Relay fallback

```mermaid
sequenceDiagram
  participant A as Sender
  participant B as Beacon
  participant C as Dest

  A->>B: 0x05 Relay [sender4B][dest4B][pilot packet 34B+payload]
  Note over B: relayWorkers = NumCPU*2, queue cap 131K
  B->>C: 0x06 RelayDeliver [sender4B][payload]
  C-->>B: 0x05 Relay (reply)
  B-->>A: 0x06 RelayDeliver (reply)
```

**Escalation is monotonic.** Within a single Dial: direct → hole-punch → relay, never the reverse.

### 4.4 Trust handshake — `pkg/daemon/handshake.go`

```mermaid
sequenceDiagram
  participant Req as Requester
  participant Reg as Registry
  participant App as Approver
  participant PC as pilotctl approve

  Note over Req,App: port 444 PortHandshake<br/>JSON HandshakeMsg

  Req->>Req: SendRequest<br/>sig over "handshake:peer:me"
  alt direct reachable
    Req->>App: handshake_request
  else private peer
    Req->>Reg: RequestHandshake (relay)
    Reg->>App: relayed request
  end
  App->>App: handleRequest (handshake.go:383-425)
  alt already trusted or mutual pending
    App-->>Req: handshake_accept auto
  else same network
    App-->>Req: handshake_accept auto
    App->>Reg: ReportTrust
  else manual
    App->>App: add to pending
    PC->>App: ApproveHandshake (line 749)
    App->>Reg: ReportTrust
    App->>Reg: RespondHandshake
    App-->>Req: handshake_accept
  end
```

**Purpose.** Mutual *authorization*, orthogonal to the *confidentiality* layer (§6). PILK/PILA gives you a confidential channel to anyone; this says whether you should have one.
**Registry role.** Not a mediator for approval. It (a) relays handshakes for peers that can't accept inbound on 444, (b) records approved pairs (`ReportTrust`), (c) enforces trust on authorize-resolve.
**Transport.** Port 444, JSON `HandshakeMsg{type,node_id,public_key,justification,signature,reason,timestamp}`.

---

## 5 · Data plane

### 5.1 Connection state machine — `pkg/daemon/ports.go:192-203`

```mermaid
stateDiagram-v2
  [*] --> Closed
  Closed --> Listen: Listen port
  Closed --> SynSent: DialConnection\nsend SYN
  Listen --> SynReceived: recv SYN\nsend SYN-ACK
  SynSent --> Established: recv SYN-ACK\nsend ACK
  SynReceived --> Established: recv ACK\n(daemon.go:1759)
  Established --> FinWait: CloseConnection\nsend FIN\n(daemon.go:2615-2657)
  Established --> TimeWait: recv FIN\nCloseRecvBuf\nsend FIN-ACK\n(daemon.go:1824-1865)
  FinWait --> TimeWait: recv FIN-ACK
  TimeWait --> Closed: idleSweepLoop\nafter TimeWaitDuration
  Established --> Closed: recv RST\nclose RecvBuf
  FinWait --> Closed: retx exhausted\nsend RST
  SynSent --> Closed: DialTimeout
```

Enum: `Closed · Listen · SynSent · SynReceived · Established · FinWait · CloseWait · TimeWait` (iota).

### 5.2 Send path

```mermaid
flowchart TD
  A[app.Write] --> B[driver.Conn.Write<br/>pkg/driver/conn.go]
  B -- cmdSend over /tmp/pilot.sock --> C[daemon ipc.handleIPCMessage<br/>pkg/daemon/ipc.go]
  C --> D[SendData<br/>pkg/daemon/daemon.go:2195]
  D --> E{NoDelay?}
  E -- no --> F[NagleBuf accumulate]
  E -- yes --> G[sendDataImmediate<br/>daemon.go:2291]
  F -- MSS=4096 or timeout --> G
  G --> H[assemble Packet<br/>34B header + payload]
  H --> I[CRC32 checksum]
  I --> J[retx buffer<br/>Connection.Unacked]
  J --> K[encryptFrame<br/>AES-256-GCM + PILS magic]
  K --> L{relay peer?}
  L -- yes --> M[wrap BeaconMsgRelay<br/>0x05 sender4B dest4B payload]
  L -- no --> N[direct UDPConn.WriteToUDP]
  M --> O[(beacon)]
  N --> P[(peer)]
  O -.-> P
```

**Windowing.** Receiver advertises window in segments (`conn.RecvWindow()`); sender tracks peer budget in bytes (`conn.PeerRecvWin`, updated on every ACK).

### 5.3 Receive path

```mermaid
flowchart TD
  A[UDP packet on wire] --> B[tunnel.readLoop<br/>tunnel.go:493]
  B --> C{magic bytes}
  C -- PILK/PILA --> D[key exchange<br/>pkg/secure/secure.go]
  C -- PILP --> E[NAT punch ack]
  C -- PILT --> F[plaintext header parse]
  C -- PILS --> G[decryptFrame<br/>AES-GCM open]
  G --> H{replay?<br/>per-peer nonce bitmap<br/>tunnel.go:52-96}
  H -- yes --> X[drop]
  H -- no --> F
  F --> I{Protocol}
  I -- 0x01 Stream --> J[handleStreamPacket<br/>daemon.go:1616]
  I -- 0x02 Datagram --> K[handleDatagramPacket]
  I -- 0x03 Control --> L[handleControlPacket]
  J --> M[OOOBuf insert<br/>ports.go:94]
  M --> N[DeliverInOrder<br/>ports.go:766-851]
  N --> O[ipc.DeliverData connID,bytes]
  O --> P[driver.Conn recvCh]
  P --> Q[app.Read]
```

### 5.4 Retransmission + congestion control

```mermaid
flowchart TD
  subgraph Tx[Tx path]
    S[SendData segment] --> T[TrackSend<br/>push retxEntry<br/>data,seq,sentAt,attempts,sacked]
    T --> U[Unacked ring]
  end

  subgraph Loop[retxLoop goroutine<br/>daemon.go:2441-2482]
    TIC[ticker RetxCheckInterval] --> SCAN{scan Unacked}
    SCAN -->|sacked| SKIP[skip]
    SCAN -->|age > RTO| RX[retransmit oldest non-sacked<br/>one per RTO period]
  end

  subgraph Ack[Incoming ACK path<br/>ports.go ProcessAck 572-673]
    A[ACK arrives] --> DUP{dup count}
    DUP -->|=3| FR[Fast retransmit<br/>SSThresh=cwnd/2<br/>cwnd=SSThresh+3*MSS]
    DUP -->|>=4| INF[cwnd += MSS per dup]
    DUP -->|cumulative| NRM{cwnd phase}
    NRM -->|cwnd < ssthresh| SS[Slow start<br/>cwnd += bytesAcked]
    NRM -->|cwnd >= ssthresh| CA[Cong avoid<br/>cwnd += MSS*b/cwnd]
    A --> RTT[updateRTT SRTT,RTTVAR<br/>RFC 6298 alpha=1/8 beta=1/4]
    RTT --> RTO[RTO = SRTT + max gran,4*RTTVAR<br/>clamp 200ms..10s]
  end

  SACK[SACK block arrives] -.-> MARK[mark retxEntry.sacked=true<br/>ports.go:927-946]
  MARK -.-> U

  RX --> LOSS{new loss event?}
  LOSS -->|yes| NL[SSThresh=cwnd/2<br/>cwnd=InitialCongWin=40KB<br/>RTO *= 2 + jitter 0-25%<br/>InRecovery=true]
  LOSS -->|no| X[skip reduction]
  NL --> U
  A --> RX2{ack >= RecoveryPoint?}
  RX2 -->|yes| EXIT[InRecovery=false]
```

**SACK format.** 4-byte magic + 1-byte count + N×8 bytes (Left, Right), max 4 blocks (RFC).

### 5.5 Out-of-order reassembly — three-phase `DeliverInOrder`

```mermaid
flowchart TD
  P[packet with payload<br/>seq s] --> CLK[Phase 1 · lock RecvMu]
  CLK --> CMP{seq vs ExpectedSeq}
  CMP -->|s < ES| DUP[drop duplicate]
  CMP -->|s > ES| BUF{OOOBuf full?<br/>MaxOOOBuf=128}
  BUF -->|no| INS[insert into OOOBuf<br/>dedup via hasOOOSeg]
  BUF -->|yes| DRP[drop]
  CMP -->|s == ES| COL[collect into toDeliver<br/>drain OOOBuf for newly-contiguous]

  COL --> REL[Phase 2 · release RecvMu]
  REL --> DEL[deliver toDeliver one-by-one<br/>1s timeout per seg to RecvBuf]
  DEL --> OK{all delivered?}

  OK -->|yes| ADV[Phase 3 · re-acquire RecvMu<br/>advance ExpectedSeq]
  OK -->|partial| REB[Phase 3 · re-insert undelivered<br/>back into OOOBuf]
  ADV --> RET[return ExpectedSeq = cumulative ACK]
  REB --> RET

  INS -. later packet fills gap .-> CMP
  RET --> SACK[sendDelayedACK<br/>daemon.go:1989-1997]
  SACK -->|OOOBuf non-empty| SB[attach SACK blocks<br/>up to 4 ranges]
```

**FIXED-001 (RecvBuf sequence leak).** Phase-2 releases `RecvMu` so blocking delivery to RecvBuf can't deadlock with the sender's ACK-update path. Phase-3 only advances `ExpectedSeq` for segments actually delivered.

### 5.6 Graceful close

```mermaid
sequenceDiagram
  participant AppA as App A
  participant DA as Daemon A
  participant DB as Daemon B
  participant AppB as App B

  AppA->>DA: Close
  DA->>DA: CloseConnection (daemon.go:2615-2657)
  DA->>DB: FIN seq=SendSeq (tracked in Unacked)
  DA->>DA: CloseRecvBuf, state=FinWait
  DA-->>AppA: io.EOF on Read
  DB->>DB: handleStream FIN branch (daemon.go:1824-1865)
  DB->>DB: CloseRecvBuf, state=TimeWait, clear Unacked
  DB-->>AppB: io.EOF on Read
  DB->>DA: FIN-ACK (ack=FIN_seq+1)
  DA->>DA: state=TimeWait
  Note over DA,DB: idleSweepLoop reaps TimeWait after TimeWaitDuration
  Note over DA: if retx exhausted in FinWait → send RST, state=Closed
```

**`io.EOF` is load-bearing.** Go's HTTP body reader requires the exact sentinel — a wrapped error breaks response parsing. `CloseRecvBuf` → `recvCh` close → `Read` returns `io.EOF`, paired with `CmdCloseOK` so both sides unblock promptly.

---

## 6 · Cryptography — `pkg/secure/`

```mermaid
sequenceDiagram
  participant C as Client
  participant S as Server
  Note over C,S: pkg/secure/secure.go:275-376

  C->>S: PILK + 32B X25519 ephemeral pubkey
  S->>C: PILK + 32B X25519 ephemeral pubkey
  Note over C,S: ECDH shared secret<br/>HKDF-SHA256 "pilot-secure-v1" | 0x01<br/>→ 32B AES key → AES-256-GCM cipher
  Note over C,S: Optional mutual auth inside encrypted channel
  S->>C: AuthFrame nodeID+ts+nonce+Ed25519sig (92B)
  C->>S: AuthFrame
  Note over C,S: sig binds: "pilot-secure-auth:" + nodeID + ephPubKey + ts + nonce
  Note over S: replay cache: 1h window, 100k entries
```

**Per-packet.** 12-byte nonce = `prefix(4B role) || counter(8B)`, AAD = prefix. Server prefix `0x00000001`, client `0x00000002` — disjoint nonce spaces so both sides can send concurrently without collision.

**Forward secrecy.** X25519 keys are ephemeral; an attacker recording ciphertext gets nothing from compromising a long-term key.

**Rekey.** Not automatic. Triggered by decrypt failure (`encrypted packet but no key`). Rate-limited 3s per peer (`tunnel.go:191,209`).

---

## 7 · Client surface

### 7.1 Driver & IPC — `pkg/driver/`

```mermaid
flowchart LR
  subgraph Client
    CLI[pilotctl / SDK / gateway]
    ipc[[ipcClient.sendAndWait<br/>wmu write lock]]
  end
  CLI --> ipc
  ipc -- [4B len][1B cmd][payload] --> S[/tmp/pilot.sock/]
  S --> H[daemon.handleIPCMessage<br/>pkg/daemon/ipc.go]
  H --> SW{cmd byte}
  SW -- 0x01 Bind --> Lf[Listen → boundPort]
  SW -- 0x03 Dial --> Dl[DialConnection → connID]
  SW -- 0x06 Send --> SD[SendData]
  SW -- 0x07 Recv --> RD[register recvCh]
  SW -- 0x0F Handshake --> HS[trust handshake]
  SW -- ... --> other[other handlers]
  H -- [4B len][1B cmdOK][payload] --> ipc
```

**Wire format.** `[4B len][1B cmd][payload]`. JSON for control, raw bytes for data.
**Write mutex.** `ipcConn` serializes multi-frame commands so responses don't interleave.
**Deadlines.** `SetReadDeadline` starts a timer goroutine that closes `deadlineCh`; `Read` blocks in a `select` over `recvCh + deadlineCh`.
**Remote close.** Daemon sends `CmdCloseOK` when peer FIN arrives → driver closes `recvCh` → next `Read` returns `io.EOF`.

### 7.2 HTTP-over-Pilot

```mermaid
flowchart LR
  subgraph Caller[net/http client]
    H[http.Client]
    T[Transport.Dial = driver.Dial]
  end
  subgraph Callee[net/http server]
    L[http.Server]
    Ln[net.Listener = driver.Listen]
  end
  H --> T --> ipc1[[ipcConn<br/>wmu serializes writes]]
  ipc1 -- cmdDial --> D[(Daemon)]
  D -. Pilot stream .- D2[(Daemon peer)]
  D2 -- cmdAccept --> ipc2[[ipcConn]]
  ipc2 --> Ln --> L
  Ln -. SetReadDeadline →<br/>deadlineCh close .- ipc2
```

Bugs previously fixed (all in driver, referenced by memory): `ipcConn` write-mutex; `Conn.Read` returning `io.EOF` (not `fmt.Errorf`); `SetReadDeadline` actually aborting blocked reads; remote close propagation via `CmdCloseOK`.

### 7.3 Gateway — `pkg/gateway/`

```mermaid
flowchart TD
  M[gateway.Map pilotAddr, ""] --> A[allocate IP from 10.4.0.0/16]
  A --> AL[addLoopbackAlias ip<br/>Linux: ip addr add<br/>macOS: ifconfig lo0 alias]
  AL --> LST[net.Listen on ip:port<br/>ports 80,443,1000-1002,7,8080,8443]
  LST --> AC{accept TCP?}
  AC -- yes --> S[driver.Dial pilotAddr:port]
  S --> CP[io.Copy bidirectional]
  CP --> AC
  LST -. Stop .- DEL[removeLoopbackAlias + listener.Close]
```

Bridges legacy IP apps into the overlay without code changes. Linux ports <1024 need root. Aliases must be torn down on `Stop()` or they persist.

### 7.4 SDKs — `sdk/`
Language wrappers around IPC: Go (native driver), Node (`@pilotprotocol/node-sdk`), Python (`pilotprotocol`). Each re-implements the IPC client only; none re-implements the wire protocol or crypto.

---

## 8 · Applications

---

## 9 · Operations

### 9.1 Updater — `pkg/updater/` + `cmd/updater/`

```mermaid
flowchart TD
  S[start] --> C0[checkOnce immediate]
  C0 --> TK[ticker 1h + jitter 0-30s]
  TK --> POLL[GET api.github.com/repos/.../releases/latest]
  POLL --> NEW{tag > local version<br/>.pilot-version}
  NEW -->|no| TK
  NEW -->|yes| DL[download archive asset]
  DL --> SHA[SHA256 of archive]
  SHA --> CS[download checksums.txt]
  CS --> VER{hash matches?}
  VER -->|no| ABORT[abort + alert]
  VER -->|yes| EXT[extractTarGz to staging dir]
  EXT --> CL{per binary}
  CL -- allowed: daemon,pilotctl,gateway,updater --> SWAP[os.Remove dst then io.Copy<br/>handles text file busy]
  CL -- skip: registry,beacon,rendezvous,nameserver --> NOP[no-op]
  SWAP --> WV[write .pilot-version tag]
  WV --> SIG[SIGTERM daemon<br/>systemd restarts process]
  SIG --> TK
```

**Safety rail.** Only client binaries are updateable. Server binaries (`registry, beacon, rendezvous, nameserver`) are explicitly skipped — a bad release cannot auto-roll the rendezvous.

### 9.2 Integration test harness — `tests/integration/local/`

```mermaid
flowchart LR
  subgraph Runner[runner · tests/integration/local]
    SH[test_*.sh]
    LIB[_lib.sh]
  end
  subgraph Compose[docker compose overlays]
    B[docker-compose.multi.yml]
    N[...nat.yml]
    C[...chaos.yml]
  end
  subgraph Image[Dockerfile.multi]
    STG1[builder: golang:1.25-bookworm<br/>builds pilot-rendezvous, pilot-daemon,<br/>pilotctl, pilot-gateway]
    STG2[runtime: debian:bookworm-slim<br/>bash curl jq procps iproute2 iptables xxd]
  end

  SH --> LIB
  LIB --> B
  SH -.->|nat suite| N
  SH -.->|chaos suite| C
  B --> STG2
  STG1 --> STG2

  B --> SV[services: rendezvous, agent-a/b/c,<br/>nat-gw, gateway]
  SV --> CH{chaos?}
  CH -->|yes| TC[tc qdisc add dev eth0 root netem<br/>delay loss reorder<br/>chaos_helpers.sh]
  CH -->|no| NET[plain bridge / custom subnet]

  SH --> TRAP[trap cleanup EXIT]
  SH --> BOOT[boot_nat_stack → compose up -d]
  BOOT --> WAIT[wait_registered · wait_for<br/>WAIT_BUDGET × PILOT_TEST_WAIT_MULT]
  WAIT --> STEPS[echo_rt · establish_trust ·<br/>agent_node_id · topology_helpers.sh]
  STEPS --> RES[logs/runs/YYYY-MM-DDTHH-MM/<br/>.captured/<test>.out]
  RES --> RC[exit code 0 if PASSED==TOTAL]
```

**Chaos injection:** `tc netem` inside containers (NET_ADMIN in compose); `sch_netem` kernel module required. **NAT suites** use iptables inside a dedicated `nat-gw` service to emulate full-cone / restricted / symmetric cones.

---

## 10 · End-to-end flows

### 10.1 Cold start
1. Daemon loads Ed25519 identity from `~/.pilot/identity.json`.
2. Opens **temp** UDP socket → Discover to beacon → DiscoverReply returns external `(IP:port)`.
3. Closes temp socket; binds real UDP socket on the same port.
4. Spawns `readLoop`, `retxLoop`, `idleSweepLoop`, heartbeat ticker, delayed-ACK timer.
5. TCP to registry; signed Heartbeat with external endpoint published.
6. IPC listener up.

### 10.2 A dial, end-to-end

```mermaid
sequenceDiagram
  participant App as App
  participant Drv as Driver
  participant DA as Daemon A
  participant DB as Daemon B
  participant AppB as Peer app

  App->>Drv: Dial(addr)
  Drv->>DA: cmdDial(addr) via /tmp/pilot.sock
  DA->>DA: DialConnection (daemon.go:2081)
  DA->>DA: ensureTunnel
  DA->>DB: PILK ephemeral pubkey (UDP)
  DB-->>DA: PILK ephemeral pubkey
  opt authenticated KEX
    DA->>DB: PILA AuthFrame (Ed25519)
    DB-->>DA: PILA AuthFrame
  end
  Note over DA,DB: HKDF → AES-256-GCM cipher, PILS from here on
  loop directRetries < 3
    DA->>DB: SYN
    alt SYN/ACK within RTO (1s..8s exp backoff)
      DB-->>DA: SYN/ACK
      DA->>DB: ACK
      Note over DA,DB: Established
    else RTO elapses
      DA->>DA: rto *= 2 (cap DialMaxRTO=8s)
    end
  end
  alt direct failed & beacon configured
    DA->>DA: SetRelayPeer(true) (daemon.go:2157-2162)
    loop relayAttempts < 3
      DA->>DB: SYN (via beacon 0x05 Relay)
      DB-->>DA: SYN/ACK (0x06 RelayDeliver)
      DA->>DB: ACK
    end
  else still failing
    DA-->>Drv: ErrDialTimeout
  end
  DA-->>Drv: connID
  Drv-->>App: Conn
```

### 10.3 Becoming reachable
The daemon's external endpoint comes from the beacon, publishes via registry heartbeat. A peer looking you up gets your current `realAddr`. If direct fails, the peer asks the beacon to coordinate a punch; if both NATs are symmetric, the peer flips to relay.

### 10.4 Trust lifecycle
1. `pilotctl handshake <peer>` → `SendRequest` (direct 444 or registry-relayed).
2. Approver's daemon files to `pending`.
3. `pilotctl approve <request>` → `ApproveHandshake` → `regConn.ReportTrust` → `sendAccept`.
4. Both sides see each other in network membership on subsequent lookups.
5. Revoke uses same message shape with `type=handshake_revoke`.

### 10.5 Version upgrade
Updater ticks hourly → new tag → SHA256 match → replace client binaries → SIGTERM daemon → systemd restarts. Rendezvous is never touched.

---

## 11 · Invariants at a glance

- **Nonce prefix disjoint.** Server `0x00000001`, client `0x00000002`.
- **STUN before tunnel.** Discovery uses a temp socket; the real socket binds afterward on the same port.
- **Registry ops serialized** on a single TCP conn via `ConnMu`.
- **Phase-2 of DeliverInOrder drops the lock.** Otherwise RecvBuf blocking deadlocks with the ACK path (FIXED-001).
- **`ExpectedSeq` advances only after confirmed delivery** (Phase-3).
- **Client binaries are updateable; server binaries are not.**
- **Trust ≠ crypto.** PILK/PILA = confidentiality. Trust handshake on port 444 = authorization.
- **NAT escalation is monotonic.** Direct → hole-punch → relay, never the reverse within a single Dial.
- **`io.EOF` is load-bearing.** Go HTTP's body reader requires the exact sentinel.

---

## 12 · File index

| Concern | Paths |
|---|---|
| Packet header / address / checksum | `pkg/protocol/packet.go`, `address.go`, `header.go`, `checksum.go` |
| Daemon core | `pkg/daemon/daemon.go` (Dial, handleStreamPacket, SendData), `ipc.go`, `handshake.go` |
| Tunnel I/O | `pkg/daemon/tunnel.go` (TunnelManager, readLoop, writeFrame, crypto state) |
| Connection / retx / cwnd | `pkg/daemon/ports.go` (Connection, retxEntry, flow control constants) |
| Crypto | `pkg/secure/secure.go` (ECDH, AES-GCM, Ed25519 auth) |
| Registry | `pkg/registry/server.go`, `client.go`, `wire.go`, `wal.go` |
| Beacon | `pkg/beacon/server.go`, `pkg/protocol/header.go` (msg type constants) |
| Driver / IPC | `pkg/driver/driver.go` (public API), `conn.go`, `ipc.go` |
| Gateway | `pkg/gateway/gateway.go` |
| Updater | `pkg/updater/updater.go`, `cmd/updater/main.go` |
| Rendezvous binary | `cmd/rendezvous/main.go` |
| Pilotctl | `cmd/pilotctl/main.go` |
| Nameserver | `cmd/nameserver/main.go` |
| Integration tests | `tests/integration/local/*.sh`, `Dockerfile.multi`, `docker-compose.multi*.yml` |
