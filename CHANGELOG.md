# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes are on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

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
