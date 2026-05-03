# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes for tagged versions are published on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

## [Unreleased]

## [1.9.1-rc2] - 2026-05-03

Release candidate 2. Builds on rc1 with three classes of fixes:

### Performance — cold pilotctl latency

- pilotctl `send-message` cold latency cut from 10–30 s to ~600 ms; warm
  to ~170 ms. Combination of:
  - Daemon-side hostname cache (60 s, persisted to
    `~/.pilot/hostname_cache.json`, reloaded at startup).
  - PolicyRunner `fetchMembers` exponential backoff so a doomed
    `list_nodes` no longer holds the regConn mutex every 5 s.
  - `DialInitialRTO` 1 s → 250 ms — three direct retries now total
    ~1.75 s before relay flip (was ~7 s).
  - Background pre-warm of the registry resolve cache for trusted
    peers at daemon start.
- Resolve prewarm runs in a goroutine after a successful
  `resolve_hostname` so the follow-up `DialAddr` skips the second
  registry round-trip.

### Reliability

- Beacon `--advertise-addr` flag — MIG instances behind a public DNAT
  now register the public ingress address instead of their internal
  VPC IP. Without this, `beacon_list` returned 10.x addresses that
  off-VPC clients couldn't reach (silent black-hole). Daemon-side
  filter (`filterUnreachable` in `beacon_select.go`) drops RFC1918 /
  loopback / link-local literals from discovered lists as a safety
  net.
- `ErrPendingDropped` sentinel in `pkg/daemon/tunnel.go`.
  `DialConnection` no longer aborts when a SYN is queued during
  tunnel-handshake startup — falls through to its existing 6-retry
  loop instead. Eliminates the spurious "send SYN: pending queue
  full" failures users saw immediately after daemon restart.
- `pilotctl ping` — added `SetReadDeadline` before the echo read so a
  relay-degraded peer reports timeout instead of hanging forever.
- `pilotctl connections` — `PEERWIN` no longer renders as
  `17179869184.0 GB` for connections in `SYN_SENT`. Was a `int(-1)` →
  `uint64` wrap in the formatter.

### CLI / docs

- 56 doc files corrected (formal `web/src/pages/docs/` + `plain/docs/`
  twins, plus 47 blog posts) — stale trust/discovery/pubsub/network-
  join/tag/install patterns updated to current command surface.
- `pilotctl` friendlier hints: `classifyDaemonError` recognizes
  `pending queue full` and `dial timeout` patterns and surfaces an
  actionable message instead of generic "check ping" boilerplate.

### Fixed — relay-flag flap (the "ping works for a minute then dies" bug)

- `clearRelayOnDirectLocked` (the relay→direct auto-recovery heuristic)
  was unreliable: after 3 consecutive non-beacon-sourced packets it
  flipped the relay flag back to direct, the next outgoing packet went
  direct (against a peer genuinely behind NAT), and writeFrame's silent-
  detection took ~60 s to flip BACK to relay. During that window
  encrypted sends to a now-direct peer dropped, and rekey attempts
  rotated session keys faster than they settled — user-visible symptom
  was "ping works for the first burst, then dial timeout for minutes".
  Triggered in production by GCP NAT-port-rewrite of beacon-originated
  UDP replies (made beacon packets look non-beacon-sourced) and by
  beacon-mesh forwards that arrive from a different IP.
- The auto-recovery is now disabled. Once a peer is on relay, only an
  explicit operator action (`SetRelayPeer(node, false)`) clears the
  flag. Recovery to direct will happen naturally on the next dial cycle.
- `handleAuthKeyExchange` and `handleKeyExchange` now ALWAYS overwrite
  the peer's UDP entry to the beacon and set+pin the relay flag when
  `fromRelay=true`, regardless of whether `ensureTunnel` previously
  registered the peer with its registry-published direct address. The
  old "only if peer was unknown" gate (issue #199) was leaving the
  relay flag false for peers that ensureTunnel had pre-registered, so
  writeFrame would happily send to the (unreachable) direct address
  until silent-detection eventually flipped it.
- New `relayPinned` map tracks "relay flag set by an authoritative
  signal" — registry's `relay_only=true`, dial-time direct-failure
  switch, ICMP-unreachable threshold, or beacon-sourced key exchange.
  Pinned peers cannot be auto-cleared.

### Performance — cold pilotctl latency

- pilotctl `send-message` cold latency cut from 10–30 s to ~600 ms; warm
  to ~170 ms. Combination of:
  - Daemon-side hostname cache (60 s, persisted to
    `~/.pilot/hostname_cache.json`, reloaded at startup).
  - PolicyRunner `fetchMembers` exponential backoff so a doomed
    `list_nodes` no longer holds the regConn mutex every 5 s.
  - `DialInitialRTO` 1 s → 250 ms — three direct retries now total
    ~1.75 s before relay flip (was ~7 s).
  - Async pre-warm of the registry resolve cache after a successful
    `resolve_hostname` so the follow-up `DialAddr` skips the second
    registry round-trip.

### Reverted

- An earlier rc2-dev variant pre-warmed encrypted tunnels for trusted
  peers at daemon start by firing ECDH key exchanges in a 350 ms
  burst. Triggered a rekey thundering-herd: every prewarm call marked
  `pendingRekey`, the retransmit loop pounded all peers at once, and
  peers' replies were interpreted as fresh requests, rotating session
  keys faster than encrypted packets could decrypt. A second variant
  (resolve-cache-only prewarm) caused a NAT-punch wave that took
  ~70 s to settle. Both reverted to lazy-on-first-use; the only
  prewarm that survives is the per-call resolve prewarm in the
  `resolve_hostname` IPC handler.

## [1.8.0] - 2026-04-20

## [1.7.2] - 2026-04-10

## [1.7.1] - 2026-04-09

## [1.7.0] - 2026-04-09

## [1.6.2] - 2026-04-08

## [1.6.1] - 2026-04-08

## [1.6.0] - 2026-04-08

## [1.5.1] - 2026-04-05

## [1.5.0-rc1] - 2026-03-27

## [1.4.1] - 2026-03-24

## [1.4.0] - 2026-03-23

## [1.3.0] - 2026-03-15

## [1.2.2] - 2026-02-18

## [1.2.1] - 2026-02-17

## [1.2.0] - 2026-02-10

## [1.1.1] - 2026-02-09

## [1.1.0] - 2026-02-08

[Unreleased]: https://github.com/TeoSlayer/pilotprotocol/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.8.0
[1.7.2]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.7.2
[1.7.1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.7.1
[1.7.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.7.0
[1.6.2]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.6.2
[1.6.1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.6.1
[1.6.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.6.0
[1.5.1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.5.1
[1.5.0-rc1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.5.0-rc1
[1.4.1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.4.1
[1.4.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.4.0
[1.3.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.3.0
[1.2.2]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.2.2
[1.2.1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.2.1
[1.2.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.2.0
[1.1.1]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.1.1
[1.1.0]: https://github.com/TeoSlayer/pilotprotocol/releases/tag/v1.1.0
