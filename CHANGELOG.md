# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes are on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

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
