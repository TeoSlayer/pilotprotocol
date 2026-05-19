# Spec — compat mode (HTTPS/WSS transport)

**Status:** Shipped to production 2026-05-18. Live at `wss://beacon.pilotprotocol.network/v1/compat`.
**Scope:** new transport for `pilot-daemon` that tunnels Pilot packets over WebSocket Secure to the beacon, so daemons in UDP-blocked environments (Docker on Render/Railway/Vercel/Fly/Lambda, restrictive corp networks) can still join the overlay.
**Issue:** addresses the "HTTP gateway" ask in Garry Tan's 2026-05-16 bug report.

## What actually shipped (vs. the original draft)

The draft below leaned toward Caddy + an embedded Pilot CA root from day one. Reality on `pilot-rendezvous-new` made the simpler path strictly better, so a few decisions changed during the rollout:

- **TLS terminator: nginx, not Caddy.** The production host already runs nginx 1.22 with certbot for `console.pilotprotocol.network` and `polo.pilotprotocol.network`. Adding a third server block for `beacon.pilotprotocol.network` reused the existing TLS automation. Caddy is no longer planned.
- **Cert: Let's Encrypt, not the Pilot root CA — for now.** The Pilot CA tooling (`cmd/pilot-ca`, `internal/transport/compat/roots/`) ships in the binary but the embedded root is the *dev* root (`dev-2026.pem`). Production currently uses a Let's Encrypt leaf. A future release will mint the prod root, embed it in client binaries, and flip the daemon's `-tls-trust` default back to `pinned`.
- **Daemon `-tls-trust` default: `system`, not `pinned`.** Because the production beacon uses Let's Encrypt today, `pinned` (which would only trust the embedded Pilot root) would refuse every connection. Default is `system` until the production root ships.
- **Beacon binary: `cmd/rendezvous`, not `cmd/beacon`.** Production runs the combined `pilot-rendezvous` (registry + beacon in one process). The WSS bridge is wired via a new `-wss-addr` flag plumbed to `pkg/beacon.Server.EnableCompatWSS`. The pubkey resolver reads from the in-process registry's `LookupPublicKey`.
- **Rollout phases 1-6 (and the originally-deferred relay-worker integration) all shipped together.** See the "Rollout — what shipped" section at the bottom.

The draft text below is preserved for design context. Where reality diverges, the section above is authoritative.

## Why this exists

Today every Pilot daemon must bind a public UDP socket (directly or via beacon hole-punch). On modern container PaaS (Render, Railway, Vercel, Lambda) UDP is impractical: either the platform doesn't expose UDP ports at all, or the symmetric NAT defeats hole-punching. Garry Tan's bug report explicitly calls this out — the catalogue is the killer feature, the UDP transport is the barrier.

**Compat mode** is a second transport for the daemon: instead of binding a UDP socket, the daemon opens a long-lived WebSocket Secure connection to the beacon on TCP port 443. Each WS binary frame carries exactly one Pilot packet, both directions. The beacon's existing relay machinery shuttles those packets to/from UDP peers.

End-to-end Ed25519 trust is unchanged. TLS provides the encrypted channel and server-auth (the daemon knows it's talking to a real beacon); Ed25519 provides peer-auth (the specialist knows the caller is who they say they are). Compat mode is a wire change, not a trust-model change.

## Goals

1. A daemon in a UDP-blocked Docker container can join the Pilot overlay and roundtrip queries against any specialist.
2. UDP daemons (today's specialists, today's clients) need **zero code changes** to talk to compat-mode peers.
3. The 4-cell transport matrix all works:
   - UDP ↔ UDP — unchanged
   - UDP ↔ WSS — beacon translates
   - WSS ↔ UDP — beacon translates
   - WSS ↔ WSS — beacon shuttles between two WS conns
4. Compat mode is opt-in (CLI flag) for the first release; later auto-fallback after N seconds of UDP failure.
5. TLS pinning to a Pilot-controlled root CA. Standard PKI compromise of public CAs cannot MITM compat daemons.
6. Works through ~all commercial firewalls. Documented escape hatch for TLS-intercepting corp proxies.

## Non-goals

- Direct browser/curl access to specialists. (That's a separate centralized "HTTPS gateway" service — out of scope here; can be built on top of compat mode later.)
- Domain-fronting / ECH / GFW-bypass. State-level censorship resistance is a separate, much larger project.
- Removing UDP. UDP remains the primary transport. Compat mode is an alternative for hosts that can't use it.

## The transport matrix

| Source | Destination | Path |
|---|---|---|
| UDP daemon | UDP daemon (direct) | unchanged — direct UDP, or beacon UDP-relay if NAT-bad |
| UDP daemon | WSS daemon (compat) | UDP packets travel to beacon (as UDP relay); beacon writes them out as WS frames on the compat peer's conn |
| WSS daemon (compat) | UDP daemon | compat daemon writes WS frames to beacon; beacon writes them out as UDP relay packets to the destination |
| WSS daemon | WSS daemon | both terminate WSS at the beacon; beacon shuttles WS frames from one conn to the other |

The beacon is the universal hub. UDP peers don't know whether a remote is on UDP or WSS — they see `relay_only=true` in the registry and route via beacon as they do today for symmetric-NAT peers.

## Identity & trust

### Pilot root CA

- We mint our own root CA keypair (offline, e.g. on a Yubikey).
- The root CA's PEM-encoded certificate is **embedded in `cmd/daemon` via `//go:embed`** so every daemon binary ships with the trust anchor pre-pinned.
- The CA signs leaf certs for each beacon hostname (`beacon-us.pilotprotocol.network`, `beacon-eu.…`, etc.).
- Leaf certs rotate via standard `tls.Config.GetCertificate`. Root rotation is a multi-release event handled by shipping the new root in a daemon update alongside the old one (overlap window).

### TLS

- Beacon WSS listener on port 443 (or 8443 behind a reverse proxy).
- **Production setup (shipped 2026-05-18):** nginx 1.22 on `pilot-rendezvous-new` terminates TLS on :443 for `beacon.pilotprotocol.network` via a Let's Encrypt cert (certbot, auto-renewing). It reverse-proxies WebSocket upgrades to `127.0.0.1:18443` where the rendezvous binary's WSS bridge listens. The original draft assumed Caddy + a private Pilot CA root; reusing the host's existing nginx+certbot stack was strictly simpler.
- The daemon-side TLS config sets `RootCAs` to a `CertPool` containing **only** the embedded Pilot root. System CAs are not trusted by default.

### Escape hatch for TLS-intercepting corp proxies

- CLI flag `-tls-trust=pinned|system`. **Default: `system` while production uses Let's Encrypt.** Will flip back to `pinned` once the production Pilot CA root ships embedded in client binaries.
- `pinned` verifies against the Pilot root CA embedded via `//go:embed`. When the embedded root is the dev placeholder (as today), `pinned` rejects every public-CA-signed beacon cert — so users who explicitly pass `-tls-trust=pinned` against the public beacon today will fail to connect. Intentional, until the production root ships.
- `system` falls back to the OS trust store. Matches the public beacon's Let's Encrypt cert. Daemon logs a clear `WARN: TLS trust relaxed to OS store — TLS-intercepting proxies on the path can read/alter relay traffic; end-to-end Ed25519 still protects payload identity`.

### Peer authentication (post-TLS)

- After the WS upgrade succeeds, the **beacon sends a challenge** as the first server frame:
  `{"type":"auth_challenge","nonce":"<32 random bytes hex>"}`
- The daemon replies:
  `{"type":"auth_reply","node_id":<N>,"public_key":"<base64>","sig":"<base64 Ed25519 over 'compat_auth:'+node_id+':'+nonce>"}`
- The beacon verifies the signature against the registered pubkey for that nodeID (same lookup as `handleHeartbeat`). On success it stores the mapping `nodeID → *websocket.Conn` and responds with `{"type":"auth_ok"}`.
- On failure: 401 close, no retry without backoff.
- All subsequent frames are **binary frames containing one raw Pilot packet each**. Text frames are reserved for control messages (currently just auth + close + ping/pong).

## Wire format

### WS binary frames (data plane)

- One binary WS frame == one raw Pilot packet (including the 34-byte header + payload).
- Maximum frame size: 64 KB (matches Pilot's MTU cap with margin).
- Per-frame overhead: 2-14 bytes WS framing + TLS record overhead. Negligible vs Pilot's 34-byte header.

### WS text frames (control plane)

- `auth_challenge`, `auth_reply`, `auth_ok` — see above.
- `bye` — graceful close (optional; client may also just close the WS).
- Future: `rate_limit_warning`, `tier_signal`, etc.

### WS ping/pong

- Beacon sends a WS ping every **30 seconds** to keep idle proxies from culling the connection.
- Daemon must respond with pong within 10 seconds or the beacon closes the conn.

## Daemon-side architecture

### Transport interface

Today `pkg/daemon/udpio.Socket` owns the UDP FD and exposes `Send(frame []byte, dst *net.UDPAddr) error` and `Recv() (frame []byte, src *net.UDPAddr, err error)`. We extract that contract into a `daemonio.Transport` interface:

```go
type Transport interface {
    Send(frame []byte, dst Endpoint) error
    Recv() (frame []byte, src Endpoint, err error)
    LocalAddr() Endpoint
    Close() error
}

// Endpoint is opaque to higher layers — UDP impl returns *net.UDPAddr,
// WSS impl returns a wssEndpoint that wraps the beacon's logical addr.
// Equality is by content (so route-table lookups still work).
type Endpoint interface {
    String() string  // for logs
    Network() string // "udp" | "wss"
}
```

Existing UDP code becomes `udpTransport implements Transport` — behavior byte-identical, zero risk to today's daemons. New `wssTransport` is a sibling.

### wssTransport

- On `Open()`: dial WSS to configured beacon URL using the embedded root for TLS. Perform Ed25519 challenge. On success, spawn a goroutine that read-loops binary frames from the conn into a buffered `recvCh chan recvFrame`.
- `Send(frame, _ Endpoint)`: write one binary WS frame containing `frame`. The destination Endpoint is ignored — all writes go to the beacon, which knows from the packet header where to forward it.
- `Recv()`: blocks on `recvCh`. Returns the next frame with `src = wssEndpoint{addr: beaconAddr}` since from the daemon's perspective, every inbound packet "came from" the beacon. Higher layers parse the Pilot header for the real source nodeID.
- On disconnect: signal the daemon's `tunnel.go` via `recvCh` error, then trigger reconnect with exponential backoff (250ms → 30s cap).
- Idle handling: respond to server pings within 10s. The Go `gorilla/websocket` library handles this transparently if `SetPingHandler` is set correctly.

### CLI surface

```
pilot-daemon \
  -transport=udp                  # today's behavior (default for now)
  -transport=compat               # WSS-only, forces relay_only=true
  -transport=auto                 # try UDP first, fall back to compat after N=30s
  -compat-beacon=wss://...        # beacon WSS URL (default: wss://beacon.pilotprotocol.network/v1)
  -tls-trust=system               # current default while beacon uses Let's Encrypt; pinned will return once prod root ships
```

Compat mode forces `RelayOnly=true` on the daemon's registry registration so peers route via beacon.

### Tunnel manager changes

The L4 tunnel manager today maps `nodeID → *net.UDPAddr` for peer endpoints. In compat mode the daemon has no peer-specific endpoints — every peer is reached via the beacon. The simplest approach: when running with `wssTransport`, the tunnel manager treats every peer as "use the single transport endpoint" and skips hole-punch / endpoint-refresh logic entirely. The peer state machine collapses to: handshake → relay → done.

## Beacon-side architecture

### WSS listener

- **As shipped:** nginx terminates TLS on port 443 for the `beacon.pilotprotocol.network` server block and reverse-proxies WS upgrades to `127.0.0.1:18443`, where the rendezvous binary's `pkg/beacon/wss.Server` accepts plain WebSocket connections.
- After WS upgrade, beacon issues auth challenge, verifies the daemon's Ed25519 signature against `s.nodes[nodeID].PublicKey` (already in registry-shared memory if beacons co-locate with registry; otherwise an RPC to the registry).
- On success: store mapping `nodeID → *wssPeer{conn, lastSeenNano, recvCh}` in `s.wssPeers` (alongside today's `s.peers` UDP map).

### Relay path bridging

The existing relay handler reads a `MsgRelay` packet, looks up destination, and writes it via UDP. New behavior:

```go
func (s *Server) routeRelayPacket(dst uint32, frame []byte) {
    s.mu.RLock()
    if udpAddr, ok := s.peers[dst]; ok {
        s.mu.RUnlock()
        s.udpConn.WriteToUDP(frame, udpAddr)
        return
    }
    if wp, ok := s.wssPeers[dst]; ok {
        s.mu.RUnlock()
        wp.writeBinary(frame) // serialized via wp.writeMu
        return
    }
    s.mu.RUnlock()
    s.metrics.relayUnknownDest.Inc()
}
```

Inbound from WSS: read goroutine on each `*wssPeer` reads binary frames and feeds them into the same packet dispatcher the UDP read loop uses (or a thin shim that wraps the frame as if it had arrived via UDP from the daemon's logical address).

### Resource management

- Connection cap per beacon: `MaxWSSPeers = 50000` initially (sized so the beacon stays under 8 GB RSS).
- Per-source-IP rate-limit on WSS upgrade attempts: 10/sec with a 100-burst.
- Auth challenge times out after 10 seconds — bots that don't sign get dropped.
- WSS idle (no frames + no pong) timeout: 90 seconds.

## Registry signaling

No changes. `relay_only=true` already exists today for daemons that want to hide their UDP endpoint from peers. Compat daemons set it; peers see it and route via beacon as they do for symmetric-NAT peers. The mechanism is identical to the existing flow; only the beacon's outbound write path changes when the relay target is a compat peer.

## Operational concerns

### Sizing

Per-WSS-connection cost on the beacon:
- 1 goroutine for the read loop (~8 KB stack)
- 1 buffered recvCh (~16 KB at 16-frame buffer × 1 KB avg)
- TLS state if terminated in-process (~32 KB) — N/A in shipped config (nginx fronts TLS)
- gorilla/websocket internal buffers (~64 KB)

Estimate: **~120 KB per peer** with nginx fronting (similar to the original Caddy estimate). 50k peers → ~6 GB. Current beacon VMs (`pilot-rendezvous-new`, 16 vCPU) have comfortable headroom.

### Cost at scale

Memory says current overlay is ~150M req/day, peak ~5k req/sec. If 10% of that becomes compat-mode traffic (500 req/sec), each request now traverses two TCP-and-TLS streams (in + out) instead of UDP. Approximate beacon CPU cost: ~1 vCPU per 5k req/sec of WSS relay. Linear in compat-mode share.

Egress cost is doubled for compat traffic (beacon pays for both legs). Worth modeling against revenue assumptions before flipping `-transport=auto` to default.

### Monitoring

Prometheus metrics on the beacon:
- `pilot_beacon_wss_connections_total` (counter, by outcome: auth_ok / auth_fail / tls_fail / rate_limited)
- `pilot_beacon_wss_active` (gauge)
- `pilot_beacon_wss_frames_in_total` / `_out_total` (counter)
- `pilot_beacon_relay_bridge_total{src_transport,dst_transport}` (counter; emits one of 4 label combos)
- `pilot_beacon_wss_idle_disconnects_total` (counter)

On the daemon:
- `pilot_daemon_transport` (gauge: 1=udp, 2=compat) labelled by hostname.
- `pilot_daemon_wss_reconnects_total` (counter, by reason).

### DDoS surface

Public WSS endpoint can be hit by anyone. Mitigations:
- Per-source-IP rate-limit on upgrade attempts (above).
- nginx in front lets us deploy fail2ban / rate-limit modules at the edge.
- Auth challenge requires the attacker to have a valid Pilot identity already registered — bots can't open holding-pattern WSS connections cheaply.

## Rollout — what shipped

All phases collapsed into a single deploy on 2026-05-18. Production at `pilot-rendezvous-new` (`34.71.57.205`, us-central1-a). Each step was independently reversible at the time and remains so via the snapshot artifacts.

### ✅ Phase 1 — PKI tooling (shipped, not yet in production use)
- `cmd/pilot-ca` mints root + leaf certs (subcommands: `init-root`, `issue-beacon`, `verify`).
- `internal/transport/compat/roots/` embeds the trust anchor via `//go:embed`. **Currently the dev root (`dev-2026.pem`); production root not yet minted.**
- 12 unit tests cover key usage flags, file modes, validity windows, chain integrity.
- Runbook: `docs/RUNBOOK-pilot-ca.md`.

### ✅ Phase 2 — `daemonio.Transport` interface
- `pkg/daemon/transport.Transport` defines `Send / Recv / LocalAddr / Close`.
- Existing UDP code (`pkg/daemon/udpio.Socket`) satisfies it implicitly — zero behavior change to UDP daemons.
- `pkg/daemon/transport.ErrClosed` shared by both implementations.

### ✅ Phase 3 — wssTransport client
- `pkg/daemon/transport/wss.Transport` uses `github.com/coder/websocket` for the WS client.
- CLI: `-transport=udp|compat`, `-compat-beacon`, `-tls-trust`. All explicit opt-in; `udp` is default.
- Compat mode forces `RelayOnly=true` on registration so peers route via beacon.
- 9 unit tests including auth challenge round-trip, rejection paths, idempotent Close.

### ✅ Phase 4 — Beacon WSS listener + relay bridging
- `pkg/beacon/wss.Server` — standalone WSS listener with Ed25519 challenge.
- `pkg/beacon.Server.EnableCompatWSS()` attaches it to the production beacon.
- Tier-0 destination check in `relayWorker`: if dest is connected via WSS, `WriteFrame()` bypasses the UDP sendmmsg batch path.
- `OnFrame` feeds inbound WSS frames into the existing `handlePacket` dispatch.
- Production `cmd/rendezvous` exposes `-wss-addr 127.0.0.1:18443` flag.
- `LookupPublicKey()` on the registry resolves nodeID → Ed25519 pubkey for WSS auth.
- 10 unit tests including last-writer-wins reconnect and capacity rejection.

### ✅ Phase 5 — Integration tests
- `tests/compat/` covers all 4 cells of the transport matrix via an in-process fake bridge.
- 6 integration tests (UDP↔UDP, UDP↔WSS, WSS↔UDP, WSS↔WSS, reconnect routing, unknown-dest drop).

### ✅ Phase 6 — Production deploy
- nginx server block at `/etc/nginx/sites-enabled/beacon.pilotprotocol.network` reverse-proxies WSS upgrades to `127.0.0.1:18443`.
- Let's Encrypt cert (`certbot --nginx`, expires 2026-08-17, auto-renewal scheduled).
- systemd unit `pilot-rendezvous.service` extended with `-wss-addr 127.0.0.1:18443`. Backup at `pilot-rendezvous.service.pre-compat`.
- DNS: `beacon.pilotprotocol.network A 34.71.57.205` (TTL 300, no proxy).
- Snapshot of previous binary at `/usr/local/bin/pilot-rendezvous.pre-compat-20260518-185845`.

### ✅ Phase 7 — End-to-end smoke test against production
- Local compat-only daemon (no UDP socket) connected via `wss://beacon.pilotprotocol.network/v1/compat`, registered as nodeID 203986, handshook with `list-agents` (0:0000.0002.BBE4) via beacon-relayed handshake, established encrypted tunnel via WSS↔UDP bridge, received the 1709-byte JSON directory.

## Future hardening (deferred, not shipped)

- **Production Pilot CA root.** Mint via `pilot-ca init-root` (operator action — Yubikey/offline), embed in `internal/transport/compat/roots/` alongside the dev root for one overlap release, then delete the dev root.
- **Flip daemon default `-tls-trust` back to `pinned`** in the same release the production root ships.
- **Prometheus scrape for WSS metrics** — `pkg/beacon.Server.WSSMetrics()` already exposes `UpgradeOK/Fail / AuthOK/Fail / FramesIn/Out / IdleDisconns / ActivePeers`. Need a `/metrics` handler.
- **`-transport=auto` mode** (try UDP for N seconds, fall back to compat). Currently compat is explicit opt-in.
- **Multi-beacon WSS connections** for redundancy. Today: one WSS conn per daemon; on disconnect, reconnect with exponential backoff to the same URL.

## Open questions resolved during rollout

1. ~~Caddy vs in-process TLS?~~ **Resolved: nginx.** Production already runs nginx with certbot; adding a third server block reused the existing TLS automation.
2. ~~Default `-transport=auto` cutover?~~ **Deferred** — auto-fallback is a future-release item. Today: explicit opt-in.
3. **Mark compat-mode peers in `list-agents` output?** **Resolved: silent.** Leaked deployment posture beats the marginal UX benefit.
4. **WS subprotocol negotiation.** **Shipped:** `Sec-WebSocket-Protocol: pilot.v1` set on both sides.
5. **Multi-beacon WSS connections.** **Deferred** — single conn per daemon for v1; multi-beacon redundancy is a future improvement.

## What we're NOT building

- Centralized HTTPS REST gateway. That'd be a separate service (Phase 8+) that proxies HTTPS REST → Pilot WSS. Easy to add later once compat mode is solid; doesn't belong in v1 of compat mode itself.
- HTTP/3 / QUIC. The whole point of compat mode is to use TCP/443 which firewalls don't block. QUIC is UDP and would defeat the purpose.
- WebRTC. We considered it — the data-channel ICE machinery would give us NAT traversal for free — but WebRTC requires a signaling server *and* still uses UDP for the data plane. Doesn't help our problem.

## Companion docs to update

- `web/src/pages/docs/networks.astro` + `plain/` mirror — describe transport modes.
- New `web/src/pages/docs/firewalls.astro` — "running pilot behind a firewall" with the `-tls-trust=system` escape hatch.
- `cmd/daemon/main.go` flag documentation in `configuration.astro`.
- `README.md` — one paragraph in the architecture section.

— end —
