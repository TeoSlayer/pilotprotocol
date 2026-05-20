# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes are on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

## [1.10.4] - 2026-05-19

### Fixed
- **Compat-mode WSS connection auto-recovers from drops.** Before this
  fix, when the daemon's WSS connection to the beacon died (network
  blip, nginx restart, GFW-style spoofed RST, peer-side hangup), the
  transport stayed permanently dead — every subsequent `Send` returned
  `wss send: failed to write msg: use of closed network connection`
  and a manual daemon restart was the only recovery. Observed in
  production today (v1.10.3) twice in one hour.

  The new design introduces a supervisor goroutine that owns both the
  read loop AND the reconnect lifecycle. When the underlying conn
  fails, the supervisor:
    1. tears down the dead conn
    2. waits with exponential backoff (250 ms → 30 s cap)
    3. re-dials + re-auths against the same `-compat-beacon` URL
    4. installs the fresh conn and resumes reading
  All under `lifetimeCtx`, so `Close()` interrupts an in-flight dial
  or read within ~100 ms.

  `Send` now returns the new `wss.ErrReconnecting` (instead of a raw
  conn-write error) when no live conn is installed — caller's
  higher-level retransmit (key-exchange retx, dial-retry, write-frame
  retry) refires naturally on the next conn. Transient read errors
  during the gap are no longer surfaced to `Recv()` so the daemon's
  tunnel read loop doesn't tear itself down over a temporary blip.

### Tests
- `pkg/daemon/transport/wss/zz_wss_test.go::TestReconnect_AfterServerCloseRestoresSendAndRecv`
  — `fakeBeacon` is configured to `CloseNow()` the WS conn after the
  second incoming frame. The test then drives a polling probe loop
  and asserts the supervisor (a) flags ErrReconnecting during the
  reconnect window and (b) successfully echoes a third frame on the
  newly-established conn.

## [1.10.3] - 2026-05-19

### Added
- **Compat mode is now single-port-443.** A new `-registry-trust system` flag
  on `pilot-daemon` lets the registry client validate the production cert via
  the OS x509 root store instead of requiring a pinned SHA-256 fingerprint.
  When `-transport=compat` is selected and the operator hasn't overridden
  `-registry`, the daemon now auto-targets
  `registry.pilotprotocol.network:443` with TLS + system trust — same
  hostname:port as the existing beacon WSS bridge. The two endpoints are
  multiplexed on a single nginx `listen 443;` via the stream module's
  `ssl_preread` SNI router (see `docs/RUNBOOK-compat-443-only.md`).
  Net effect: a daemon running in Render, Replit Agent, or any other
  managed-claw sandbox that allows only outbound TCP/443 can now register +
  resolve + tunnel data — **zero TCP/9000, zero UDP**.

### Changed
- `pilot-daemon -registry-tls` no longer requires `-registry-fingerprint` if
  `-registry-trust=system` is set. The two modes coexist:
    - `pinned` (default): cert pinned by SHA-256 fingerprint — back-compat
      with the existing single-VM deploy
    - `system`: OS root store — works against any publicly-trusted CA cert,
      i.e. the Let's Encrypt cert on `registry.pilotprotocol.network`

### Tests
- `tests/zz_compat_registry_tls_test.go::TestCompatRegistryTLSPinned` —
  spins up an in-process TLS registry + beacon, points a compat daemon at
  the TLS registry with a pinned cert, and verifies Register + WSS bridge
  attach end-to-end.
- `tests/zz_compat_registry_tls_test.go::TestCompatRegistryTrustSystemRejectsBadCert` —
  pins that `-registry-trust=system` refuses an untrusted self-signed cert
  (MITM defence-in-depth).

### Ops / deployment

Single runbook covers the production rollout:
[`docs/RUNBOOK-compat-443-only.md`](docs/RUNBOOK-compat-443-only.md). Steps:

1. DNS A record `registry.pilotprotocol.network → 34.71.57.205`
2. `certbot certonly --nginx -d registry.pilotprotocol.network`
3. Move existing nginx HTTP-on-443 vhosts (`beacon.*`, `console.*`,
   `polo.*`) to internal `listen 127.0.0.1:14443 ssl;`
4. Add nginx `stream {}` block: `ssl_preread` on, SNI map →
   `registry.*` to a stream-mode TLS terminator on 14444 (which proxies
   plain TCP to the existing registry on `127.0.0.1:9000`),
   everything else to 14443.
5. Smoke-test via `openssl s_client` + a real compat daemon.

Rollback is one `nginx -t && systemctl reload nginx` after restoring the
sed-backed-up sites-enabled files.

### Operational changes applied to `pilot-service-agents` (2026-05-19)

These are server-side ops changes that landed alongside the v1.10.3 code work
to make all 435+ specialist agents responsive under high traffic:

- **`/usr/local/bin/responder-wave-restart.sh` was no-op'd**. Original backed
  up alongside as `responder-wave-restart.sh.full-backup-1779223695`. The
  every-~10-min wave restart was killing in-flight reply queues across all
  agents (each restart SIGTERM'd Python responder workers mid-`pilot-send-stdin`
  subprocess), so list-agents queries from outside the fleet timed out
  even though dispatch worked. Reply latency dropped from 30s+ timeouts to
  sub-second after disabling.
- **Per-agent systemd drop-in
  `/etc/systemd/system/pilot-responder-*.service.d/high-traffic.conf`** on
  all 435 responders:
    - `RESPONDER_REPLY_WORKERS=16` (default `2`)
    - `RESPONDER_INBOX_WORKERS=6` (default `2`)
    - `RESPONDER_REPLY_QUEUE_MAX=2048`, `RESPONDER_INBOX_QUEUE_MAX=2048`
    - `RESPONDER_STALE_REPLY_AFTER=60s` (default `60s`),
      `RESPONDER_INBOX_MAX_AGE=60s`
    16 workers absorb the swarm noise (failing sends to unreachable swarm
    nodes each pin a worker for the hardcoded 25s `pilot-send-stdin`
    timeout) while leaving slots for legitimate user traffic.
- **`/opt/pilot-dashboard/metrics-snapshot.json` despiked**. The
  restart-wave at 21:29:54 UTC inflated cumulative request counters by
  2,866,001 over 133s (21,548 req/s artefact). A second pass at 21:34:11
  added another 903,719 over 103s (8,740 req/s). Both spikes flattened to
  the 300 req/s baseline rate; the excess subtracted from all subsequent
  entries to keep cumulative totals consistent. Backup at
  `metrics-snapshot.json.pre-despike-1779227221`.
- **`/opt/pilot-dashboard/server.py::/api/metrics-history` default range**
  changed from "all 17,280 samples" to **720 samples (1 hour at 5s
  intervals)**. The full buffer is ~213 MB JSON which crashed the
  network-stats page when fetched with no query params; the default now
  returns ~9 MB in ~1.6s. Callers that want the full 24h window can still
  pass `?range=17280`. Backup at
  `server.py.pre-metricshistory-default-1779227619`.

## [1.10.2] - 2026-05-19

### Fixed
- **Compat mode: outbound-initiated dials to fresh peers**. In v1.10.1, a
  compat-mode (WSS-only) daemon's first SYN to a peer went raw through the WSS
  pipe because `routing.WriteFrame` only wrapped frames in `BeaconMsgRelay`
  after the blackhole heuristic flipped the peer to relay mode (3 misses, ~8s
  silence). For brand-new peers, the unwrapped frame reached the beacon as an
  unknown protocol byte and was dropped silently — every outbound-initiated
  dial timed out. Managed claws (Docker on Render/Railway/Lambda, UDP-blocked
  corp networks) could RECEIVE traffic via the bridge but couldn't INITIATE
  connections to UDP-only peers. Fix: a `forceRelay` flag on `routing.Manager`
  set by `TunnelManager.ConnectCompat`, so every outbound write in compat mode
  is BeaconMsgRelay-wrapped regardless of blackhole state.

### Added
- `tests/zz_compat_dial_test.go` — end-to-end regression test: a compat daemon
  dials a UDP peer's echo service through an in-process beacon and asserts the
  three-way handshake completes and echo data flows both ways.
- `tests/compat/zz_real_beacon_test.go` — 4 integration tests exercising the
  production beacon binary's WSS↔UDP bridge with real `bwss.Server` +
  `dwss.Transport` (not the synthetic in-memory bridge used by the existing
  4-cell matrix).
- `beacon.Server.WSSAddr()` and `WSSIsConnected(nodeID)` — exposed for tests
  that bind to `:0` and need to wait for post-handshake WSS registration.

### Platform compatibility

Researched egress policies of common managed-claw / agent-sandbox platforms.
Verified live: a fresh compat daemon (`node_id=205787`) fetched the
weather-agent list from `list-agents` over **TCP/443 (beacon WSS) + TCP/9000
(registry), zero UDP**. From that, the picture is:

| Platform                | UDP egress         | TCP arbitrary port   | UDP mode works  | Compat mode works |
|-------------------------|--------------------|----------------------|-----------------|-------------------|
| Render                  | ❌ blocked         | ✅                   | No              | **✅ Yes**        |
| Railway                 | ✅                 | ✅                   | ✅              | ✅                |
| Fly.io                  | ✅                 | ✅                   | ✅              | ✅                |
| AWS Lambda              | ✅ (port 25 blkd)  | ✅                   | ✅              | ✅                |
| Google Cloud Run        | ✅ (via VPC)       | ✅                   | ✅              | ✅                |
| Vercel Functions        | (ephemeral; wrong runtime for a persistent daemon)                | —               | —                 |
| Modal Sandboxes         | ✅ default-allow   | ✅                   | ✅              | ✅                |
| E2B Sandboxes           | ✅ (IP rules only) | ✅                   | ✅              | ✅                |
| Daytona Sandboxes       | ✅ default-allow   | ✅                   | ✅              | ✅                |
| Cursor Cloud Agents     | allowlist-driven   | allowlist-driven     | only if allowed | only if allowed   |
| Replit Agent / Docker AI Sandbox | ❌ hard-blocked | ❌ hard-blocked  | No              | ❌ No (needs `HTTPS_PROXY`) |
| Devin (Cognition)       | undocumented; likely Docker-AI-class | ❌  | No              | likely No         |

**v1.10.2 fully unblocks**: Render (the original Garry Tan report case).
**Already worked in v1.10.0 UDP mode**: Railway, Fly.io, Lambda, Cloud Run,
Modal, E2B, Daytona.
**Still blocked in v1.10.2**: platforms enforcing the Docker AI Sandbox
HTTP-proxy-only egress model (Replit Agent, Devin, locked-down Cursor
sandboxes). These need an `HTTP_PROXY`/`HTTPS_PROXY`-honoring transport and
a registry-over-WSS bridge — tracked for v1.10.3.

## [1.10.1] - 2026-05-19

### Fixed
- **Heartbeat signature verification** (Garry Tan bug report #1): the registry-client
  signer captured `d.identity` once at startup; after key rotation, heartbeats kept
  signing with the stale identity and got rejected. Signer now reads `d.identity`
  under `d.identityMu` on every call. Affected every daemon that rotated keys
  after registration; symptom was a `"registry: signature verification failed"`
  loop with re-register every 60 s and no peer connectivity.

### Added
- **Compat mode**: tunnel Pilot packets over WebSocket Secure to the beacon for
  daemons in UDP-blocked environments (Docker on Render/Railway/Vercel/Lambda,
  restrictive corp networks). Opt-in via `-transport=compat` on the daemon;
  default behavior unchanged. Live at `wss://beacon.pilotprotocol.network/v1/compat`.
  See [docs/SPEC-compat-mode.md](docs/SPEC-compat-mode.md) and
  [docs/firewalls](https://pilotprotocol.network/docs/firewalls).
- `pilotctl skills disable` / `enable` — safe removal of the daemon's auto-installed
  agent skill files. Strip-only on co-inhabited files (`CLAUDE.md`, `AGENTS.md`,
  `AGENT.md`, `SOUL.md`); delete in our own subdirs. OpenClaw plugin allow-list
  restored from `.pilot-bak` snapshot. Idempotent.
- Marker block self-disclosure: the `<!-- pilot:begin ... -->` comment now embeds
  `Inserted by pilot-daemon. Remove with: pilotctl skills disable` so anyone
  opening their agent config file in one read knows what it is and how to remove it.
- `data_b64` field in dataexchange inbox messages (opt-in via `-dataexchange-b64`):
  lossless base64 alongside the existing `data` string for binary payloads
  (e.g. zlib-compressed HealthKit envelopes).
- `cmd/pilot-ca` offline tool to mint the future production Pilot root CA and beacon
  leaf certs; see [docs/RUNBOOK-pilot-ca.md](docs/RUNBOOK-pilot-ca.md).

### Changed
- `install.sh` post-install banner now points at `pilotctl skills disable` for users
  who want to opt out of skill auto-injection.
- Beacon's relay worker checks for a WSS-connected destination before the UDP
  tier-1/2 lookups, so existing UDP daemons reach compat-mode peers transparently
  (the bridging happens entirely on the beacon).
- Registry `LookupPublicKey(nodeID)` exposed for in-process beacon to authenticate
  WSS daemons against registered pubkeys.

## [1.9.1] - 2026-05-05

- Rekey storm fix: `decryptFailDropGrace` (3 s) prevents tearing down a freshly-installed
  `peerCrypto` before in-flight frames from the old key have drained
- AEAD divergence recovery: 5 consecutive auth failures drop `tm.crypto[peer]` and trigger
  fresh key exchange automatically
- Relay-flag pinning: `relayPinned` replaces "auto-clear after 3 direct receipts" heuristic
  that caused relay/direct flapping every ~60 s in production
- Cold `pilotctl` latency: 10–30 s → ~600 ms; warm: ~170 ms

## [1.9.0] - 2026-04-30

- Registry lock contention closed end-to-end
- P1-010 tunnel-desync recovery: salvage in-flight plaintext on peer-initiated rekey
- Registry hardening: panic recovery, WAL replay, 3-phase rotate-key/set-key-expiry
- Multi-beacon discovery; peer IPs hidden by default; member counts admin-gated

## [1.8.0] - 2026-04-20

- Auto-updater sidecar: hourly GitHub releases check, client-only binary updates
- Version reporting in all binaries; dashboard simplification

## [1.7.0] - 2026-04-09

- Gateway overlay: `pilot-gateway` TCP bridge mapping pilot addresses to local IPs
- `send-file` with resume support; Whitepaper v1.6

## [1.6.0] - 2026-04-08

- HTTP-over-Pilot: `pilotctl http` command
- Managed networks: expression-based policy engine (tag, evict, fill_trust, cycle)
- Fix: stale endpoint blackhole; registry client `Send()` concurrency; STUN/readLoop race

## [1.5.0] - 2026-03-27

- Pubsub: topic-filtered publish/subscribe
- Send-message command; nameserver plugin; flow-control window in packet header

## [1.4.0] - 2026-03-23

- Symmetric NAT relay through beacon (auto-detected)
- Restricted Cone NAT: beacon hole-punch; `DialConnection` direct→relay fallback

## [1.3.0] - 2026-03-15

- Policy engine phase 1: join rules, port gates, cycle actions
- Webhook plugin: outbound HTTP callbacks on protocol events

## [1.2.0] - 2026-02-10

- Trusted-agents auto-accept: embedded service-agent allow-list
- Security phase 2: 8 resource-exhaustion fixes; CodeQL workflow
- Fix: FIN-ACK storm bounded; `list_nodes` cache invalidation; `sendSegment` backpressure

## [1.1.0] - 2026-02-08

- Initial public release: daemon, rendezvous, `pilotctl`, gateway
- 48-bit addresses (`N:NNNN.HHHH.LLLL`), UDP tunnels, key exchange, trust model
