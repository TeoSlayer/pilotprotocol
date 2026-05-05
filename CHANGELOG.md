# Changelog

All notable changes to Pilot Protocol are recorded here. This file follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions. The
project uses [Semantic Versioning](https://semver.org/).

Detailed per-release notes for tagged versions are published on the
[GitHub Releases page](https://github.com/TeoSlayer/pilotprotocol/releases).

## [Unreleased]

## [1.9.1] - 2026-05-05

Stable release rolling up rc1–rc5. Headline themes: cold-start latency
collapse, recovery from peer-side AEAD key divergence, and relay-flag
stability. Verified end-to-end against the production rendezvous fleet.

### Fixed

- **Rekey storm with grace-period guard.** Resolved the loop where a
  peer-initiated rekey left in-flight ciphertext on the relay path
  encrypted with the old key; those frames arrived after the new key
  installed, failed AEAD, and tripped the decrypt-fail drop threshold,
  tearing down the freshly-installed `peerCrypto` and demanding yet
  another rekey. `decryptFailDropGrace = 3 * time.Second` never drops
  a `peerCrypto` installed less than the grace window ago. (rc4 + rc5)
- **Recovery from peer-side AEAD key divergence.** After 5 consecutive
  AEAD authentication failures the daemon drops `tm.crypto[peer]` and
  triggers a fresh key exchange — automatic per-peer recovery
  equivalent to a daemon restart. New `TunnelManager.DropCrypto(nodeID)`
  exposes this as a public method for operator scripts. (rc4)
- **Relay-flag pinning.** `relayPinned` map tracks "relay flag set by
  an authoritative signal" (registry, dial-loop direct exhaustion,
  ICMP-unreachable, beacon-sourced key exchange). The previous
  "auto-clear after 3 direct receipts" heuristic flapped relay state
  every ~60s in production, causing session-key rotation cascades and
  the "ping works for a minute then dial timeout for minutes" symptom.
  Auto-clear is now disabled. (rc4)

### Performance

- **Cold pilotctl latency cut from 10–30 s to ~600 ms; warm to ~170
  ms.** Combination of:
  - Daemon-side hostname cache (60 s, persisted to
    `~/.pilot/hostname_cache.json`, reloaded at startup).
  - PolicyRunner `fetchMembers` exponential backoff so a doomed
    `list_nodes` no longer holds the regConn mutex every 5 s.
  - `DialInitialRTO` 1 s → 250 ms — three direct retries now total
    ~1.75 s before relay flip (was ~7 s).
  - Background pre-warm of the registry resolve cache for trusted
    peers at daemon start. (rc2)

### Changed

- **Dial budget**: `DialMaxRetries` 6 → 7. The relay phase now gets 4
  retries (was 3), giving cold-start handshakes (key exchange + SYN/
  SYN-ACK) enough room without exceeding the user's `--timeout`. With
  `DialInitialRTO=250ms` and `DialMaxRTO=8s` exponential backoff,
  total budget is ~8 s. (rc4)
- **`pilotctl ping` per-attempt floor**: 4 s → 10 s, covering the
  daemon startup-storm warm-up window where multiple trusted peers
  concurrently establish crypto state. (rc4)
- **Beacon `--advertise-addr` flag**: MIG instances behind a public
  DNAT can now advertise a stable address. (rc2)

### Known limitations

- Against peers running pre-1.9.1 daemons, the rekey storm pattern
  may still cause occasional dial timeouts until those peers update.
  Workaround on our side: `pilotctl daemon stop && pilotctl daemon
  start`.
- Cold start: the FIRST 1–3 dials immediately after a daemon restart
  can fail while the tunnel establishes crypto. Subsequent dials
  succeed. Tracked for a future per-peer probe-and-adapt SRTT-based
  dial budget.

### Considered, reverted in development

A rough log of fixes that introduced regressions and were pulled
before GA: inbound auth-key-exchange rate-limit, recv-replay-window
reset on stale auth-key-exchange duplicate, trusted-peer tunnel
pre-warm at daemon start, and dial-timeout-exhausted crypto drop. See
the rc4 entry for details.

## [1.9.1-rc5] - 2026-05-04

Reliability fix on top of rc4. Verified 100% (30/30 cold-start sends +
50/50 warm-path sends) between two daemons on matching binaries over
the GCP relay.

### Rekey storm fix: grace-period guard on `decryptFailDropThreshold`

rc4's `decryptFailDropThreshold = 5` caught persistent peer-side AEAD
key divergence by dropping the `peerCrypto` after five consecutive
decrypt failures. With both sides on rc4, a peer-initiated rekey left
in-flight ciphertext on the relay path encrypted with the old key.
Those frames arrived at us after the new key had been installed, failed
AEAD against the new key, and within seconds tripped the threshold —
tearing down the freshly-installed `peerCrypto` and demanding yet
another rekey. The peer rotated again, its next batch of in-flight
frames repeated the pattern, and the tunnel re-established every ~5 s
in a closed loop scaling with relay queue depth.

`decryptFailDropGrace = 3 * time.Second`: never drop a `peerCrypto`
that was installed less than the grace window ago. Stale ciphertext
from the previous rotation drains in ≤1 RTT (relay round-trip
<200 ms); the grace covers worst-case salvage replay without holding
a genuinely diverged session for long. The threshold still catches
peers that remain misaligned past the grace.

## [1.9.1-rc4] - 2026-05-03

Reliability improvements for back-to-back commands and long-lived
tunnels. Verified: 35/40 (87.5%) operations succeed under aggressive
rapid-fire stress (30 immediate sends + 10 sends after 60s idle)
between two daemons running matching binaries. Up from rc3 which
hung indefinitely against the same pattern with peers running older
versions.

### Recovery from peer-side AEAD key divergence

`peerCrypto.decryptFailCount` tracks consecutive AEAD authentication
failures from a peer. After `decryptFailDropThreshold = 5` consecutive
failures, the daemon drops `tm.crypto[peer]` entirely and triggers a
fresh key_exchange. Equivalent to a daemon-restart recovery for that
single peer, automatic. Resets to 0 on any successful decrypt.

`TunnelManager.DropCrypto(nodeID)` exposes this as a public method —
operator scripts and the dial-timeout-exhausted path can force a
re-handshake without restarting the daemon.

### Relay-flag pinning

`relayPinned` map tracks "relay flag set by an authoritative signal."
Set when `ensureTunnel` sees `relay_only=true` from the registry, when
the dial loop's direct-phase exhausts and switches to relay, when ICMP-
unreachable threshold is hit, or when an authenticated key_exchange
arrives via the beacon path. `clearRelayOnDirectLocked` is now a no-op
for pinned peers — it cannot auto-flip them back to direct on stray
non-beacon-sourced packets (NAT-port-rewrite of beacon replies, beacon-
mesh forwards from a different IP, etc).

The previous "auto-clear after 3 direct receipts" heuristic flapped
relay state every ~60s in production, causing session-key rotation
cascades and the "ping works for a minute then dial timeout for
minutes" symptom. Auto-clear is now disabled entirely.

### Dial budget

`DialMaxRetries` 6 → 7. The relay phase now gets 4 retries (was 3),
giving cold-start handshakes (key_exchange + SYN/SYN-ACK round trip)
enough room without exceeding the user's `--timeout`. With
`DialInitialRTO=250ms` and `DialMaxRTO=8s` exponential backoff, total
budget is ~8 s.

### pilotctl ping per-attempt floor

`cmd/pilotctl/main.go cmdPing`: per-attempt budget floor 4s → 10s.
Covers the daemon startup-storm warm-up window where 7+ trusted peers
are concurrently establishing crypto state.

### Considered, reverted in development

* **Inbound auth-key-exchange rate-limit** (10s window with pubkey-
  aware bypass): suppressed peer-initiated rebuild attempts when the
  peer's own decryptFailDropThreshold dropped crypto for us. Both sides
  ended up stuck in "no key" state. Reverted; the handler is naturally
  idempotent for same-pubkey duplicates so processing all of them is
  cheap.
* **Recv-replay-window reset on stale auth-key-exchange duplicate**:
  introduced a different race where in-flight peer packets at high
  counters got rejected after the reset. Reverted.
* **Trusted-peer tunnel pre-warm at daemon start**: ECDH variant
  triggered a rekey storm; ensureTunnel-only variant caused a NAT-
  punch wave. Both removed.
* **Dial-timeout-exhausted crypto drop**: too aggressive — fired on
  cold-start handshake delays and made things worse. Removed.

### Known residual issues

* Against peers running older daemon versions (e.g. some service
  agents on the production fleet), the rekey storm pattern still
  causes occasional dial timeouts. The pre-existing daemons would
  benefit from being updated to rc4. Workaround for the user's side:
  `pilotctl daemon stop && pilotctl daemon start`.
* Cold-start: the FIRST 1-3 dials immediately after a daemon restart
  can fail while the tunnel is establishing crypto. Subsequent dials
  succeed. Open follow-up: per-peer probe-and-adapt SRTT-based dial
  budget so peers we've successfully reached before get a tighter
  timeout, and first-contact peers get a generous one.

## [1.9.1-rc3] - 2026-05-03

Same content as rc2; tag bump to publish a fresh signed/notarized
artifact set. The release workflow's macOS ad-hoc codesign step
(`.github/workflows/release.yml:81-91`) re-signs each darwin binary on
every tag — rc3 picks up that signature and the corresponding
`checksums.txt`.

### Tracked, not blocking rc3

- Long-running tunnels against older-version peer daemons can desync
  after ~minutes-to-hours of idle: the peer's daemon resets its send
  counter (or rotates AEAD state without rotating X25519 keys), our
  preserved peerCrypto holds a high maxRecvNonce, and the peer's
  resumed-from-1 packets get rejected as replays. User symptom: a
  burst of pings works on a fresh daemon, then `dial timeout after
  7.5 s` until daemon restart. Workaround: `pilotctl daemon stop &&
  pilotctl daemon start`. Fix candidates explored in rc2-dev (reset
  recv replay state on duplicate key exchange, reset crypto on stale
  contexts, prewarm trusted-peer tunnels) all introduced regressions
  of their own and were reverted. The structural fix is a protocol-
  level "session epoch" handshake — out of scope for the rc series.
  Adds `peerCrypto.createdAt` for a future heuristic.

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
