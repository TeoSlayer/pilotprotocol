# v1.9.0 — Release Notes

**Scope:** 96 commits since `v1.8.0` (2026-04-21 → 2026-04-30).

This is the stable v1.9.0 cut. The headline themes are: registry
lock-contention closed end-to-end, P1-010 tunnel-desync recovery,
registry hardening (panic recovery, WAL replay, 3-phase
rotate-key/set-key-expiry), multi-beacon discovery, and a privacy pass —
peer IPs hidden by default in pilotctl output and network member counts
admin-gated at the registry.

## What's new

### Registry hardening

- **Panic recovery** in registry handlers (`pkg/registry/panic_recovery.go`).
  A panicking handler no longer takes the whole server down; the panic is
  logged with a stack trace and the connection is closed.
- **WAL replay + size cap** (`pkg/registry/wal_replay.go`,
  `wal_size_cap_test.go`). The write-ahead log replays cleanly on startup
  and self-bounds to a configured size cap so a stuck `flushSave` cannot
  let the WAL grow until the volume fills.
- **3-phase pattern** applied to `handleRotateKey` and
  `handleSetKeyExpiry` — RLock for verify, unlock, Lock only for the
  mutation. Eliminates the lock-hold during signature checks.
- **Heartbeat-ack pre-build** to keep the hot path off `json.Marshal`.
- **`list_nodes` cache-invalidation hooks** wired through every membership
  mutation (5 per-net + 5 admin sites).
- **`apply_snapshot` outside-lock build** — the registry constructs the
  snapshot deep-copy without holding `s.mu`, dropping the lock-hold from
  multi-second peaks to milliseconds.
- **Snapshot lock-discipline tests** (`apply_snapshot_test.go`,
  `snapshot_lock_test.go`).

### Tunnel + dataexchange (P1-010 closure)

1. **Salvage replay** — per-peer plaintext ring buffer, re-encrypted with
   the new key after rekey. Recovers fire-and-forget RPCs sent under
   stale crypto during the rekey window. Webhook event:
   `tunnel.desync_salvage`.
2. **Rekey retransmit loop** — per-peer `pendingRekey` state and a
   bounded retransmit goroutine (every 4 s, capped at 5 retries). Closes
   the case where our `key_exchange` or the peer's reply was dropped.
   Webhook event: `tunnel.rekey_gave_up`.
3. **Salvage cap of 4 entries** — original 32 caused a replay-storm on
   rekey; 4 covers the realistic shape and is ~6 KiB/peer instead of
   ~48 KiB.
4. **Preserve nonce/replay state across duplicate `key_exchange`** —
   replace `tm.crypto[N]` only when the entry doesn't exist or the peer's
   pubkey actually changed. Pinned by
   `TestHandleKeyExchangeDuplicatePreservesCryptoState`.

### Multi-beacon discovery

`pkg/daemon/beacon_select.go`, `beacon_discovery.go`. Daemons can be
configured with a comma-separated `-beacon` list and FNV-of-pubkey-hash
to one of the live beacons. Foundation for autoscaling beacon meshes —
per-pair tunnels pin to the same beacon for ordering.

### Privacy: peer IPs no longer in pilotctl output by default

`pilotctl peers`, `pilotctl info`, `pilotctl lookup` strip
endpoint-bearing fields (`endpoint`, `real_addr`, `lan_addrs`,
`public_addr`, `stun_addr`, `observed_addr`) from their output by
default. Pass `--show-endpoints` to bring them back for ops/debug.
Searches that match endpoint substrings only resolve when
`--show-endpoints` is set, so a search prompt cannot leak IP existence.

Pinned by `cmd/pilotctl/redact_test.go::TestRedactPeerEndpointsRemovesIPFields`.

### Privacy: network member counts now admin-gated

`pkg/registry/server.go::handleListNetworks` omits the per-network
`members` count from `list_networks` responses unless the request
carries a valid `admin_token`. Network identity (id, name, join_rule,
enterprise) stays visible — daemons can still discover what to join —
but population per network is treated as a privacy-sensitive aggregate.
Pinned by `tests/network_test.go::TestListNetworksMembersAdminGated`.

The pilotctl `network list` view shows `—` in the MEMBERS column when
the count is hidden, so the redaction is visible-by-policy rather than
mistaken for broken.

`pkg/registry/client.go::ListNetworks` takes a variadic `adminToken` to
opt into seeing the count.

### Operations: runtime banner endpoint

The dashboard's amber maintenance notice (rendered above the release
banner) is now mutable at runtime via an admin-only HTTP endpoint —
`PUT /api/banner` on the rendezvous's HTTP port. Persisted to disk,
survives restart, no reconnect storm. Both `GET` and `PUT` require the
admin token; the public still sees the banner via
`/api/stats.maintenance_banner` and the dashboard HTML.

Pinned by `tests/dashboard_test.go::TestDashboardBannerEndpoint` —
8 cases (no-token GET/PUT, wrong-token, valid round-trip,
`/api/stats` surfaces banner, persistence file written, empty-body
clears, 405 on DELETE).

### `pilotctl updates`

New command to fetch the public changelog feed:

```
pilotctl updates [--count N] [--scope <category>] [--refresh]
pilotctl --json updates
```

Reads `https://teoslayer.github.io/pilot-changelog/feed.xml`, caches at
`~/.pilot/updates-cache.xml` for 5 min, falls back to stale cache when
offline. No external deps — RSS parsed with `encoding/xml`.

Pinned by 11 tests in `cmd/pilotctl/updates_test.go` (cold fetch, cache
hit, `--refresh` bypass, stale-cache refetch, offline fallback,
no-fallback-without-cache, scope filter, count truncation, combined).

### Daemon stability

- **Async IPC write queue** — buffered `sendCh` per ipcConn + single
  writer goroutine, done-channel pattern, `ErrIPCBackpressure` on slow
  clients. Eliminates the IPC-write-mutex contention bottleneck observed
  under stress. Pinned by `pkg/daemon/ipc_async_write_test.go`.
- **Pubsub retry resilience** — failed publish attempts retry once
  before raising; per-peer failure counter exposed via webhook.
  `pkg/daemon/pubsub_resilience_test.go`.
- **Lock-ordering invariants** documented in `CONTRIBUTING.md`.

### Integration suite

- **Webhook readiness helper** — `webhook_helpers.sh` waits for the
  webhook sink to be HTTP-bound before bringing up agents.
- **NAT IPAM retry** — `test_nat_dual_symmetric.sh` and the shared
  `nat_test_common.sh` sweep stale Docker networks on `pool overlaps`
  and retry the compose-up.
- **Bench harness** — `bench_relay.sh` + `docker-compose.multi.bench.yml`
  characterize relay throughput without the chaos overlay's tmpfs cap
  used by disk-full tests.
- **Lane bump 3 → 5** for parallel NAT tests.

### Release engineering

- **macOS ad-hoc codesign** in `.github/workflows/release.yml`. darwin
  builds get `codesign --force --deep --sign -` plus `xattr -cr` before
  packaging. Without this, downloaded macOS tarballs trigger
  `killed: 9` or Gatekeeper "cannot be opened because Apple cannot check
  it for malicious software" on first run. Ad-hoc signing is enough to
  let the binary launch — full notarization would need an Apple
  Developer ID and is out of scope for this release.

## Migration notes

- **External SDKs / dashboards** that call `list_networks` and read
  `members` need to either pass `admin_token` in the request or handle
  the field being absent. Pre-v1.9.0 registries keep returning the
  count to anyone; after upgrading, they don't.
- **Scripts / tooling** that grepped pilotctl output for IP fragments
  need `--show-endpoints` (or, preferably, switch to node IDs).

## Acceptance evidence

- `go vet ./...` clean.
- `go test ./...` — 15/15 packages pass.
- `go test ./... -race -count=1 -timeout 600s` — clean, zero data races.
- 8 binaries cross-build clean for `linux/{amd64,arm64}` and
  `darwin/{amd64,arm64}` with `-X main.version=v1.9.0`.
