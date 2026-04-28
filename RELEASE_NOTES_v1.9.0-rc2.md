# v1.9.0-rc2 — Release Notes

**Scope:** 11 commits since `v1.9.0-rc1` (2026-04-24 → 2026-04-27).

The headline of RC2 is **P1-010 closed** (both halves) — the
tunnel-crypto-desync class of bugs that caused fire-and-forget RPCs
(task submit, send-results) to silently lose data across rekey windows.
P1-009 closed as a side effect: the `test_midrekey_*` regression repros
all pass cleanly now.

## P1-010 — tunnel desync recovery

Four commits, four layers of the fix:

### 1. Salvage replay (`7f76e75`)

Per-peer plaintext ring buffer in `peerCrypto.salvage`. Every
encrypted send copies the plaintext into the buffer. When
`handleAuthKeyExchange` (or unauth `handleKeyExchange`) installs a
fresh `peerCrypto` because the peer's pubkey changed, we re-encrypt
the recent plaintexts with the new key and re-send via `writeFrame`.

Recovers fire-and-forget RPCs that were sent under stale crypto
during the rekey window.

Webhook event: `tunnel.desync_salvage` with replay count.

### 2. Rekey retransmit loop (`a126a26`)

Per-peer `pendingRekey` state set on `sendKeyExchangeToNode`, cleared
on first successful inbound decrypt. New goroutine
`rekeyRetransmitLoop` retransmits stale entries every 4 s, capped at
5 retries. Closes the case where our key_exchange or peer's reply was
dropped on the wire — without this, the next chance to recover was
the 5-min `RelayProbeInterval`.

Webhook event: `tunnel.rekey_gave_up` if a peer hits the retransmit
cap (real reachability problem worth investigating).

### 3. Cap salvage at 4 entries (`5de736f`)

Original cap of 32 caused a replay-storm on rekey: the dataexchange
retransmit layer's churn filled the buffer, and on rekey all 32
frames went out in a tight loop. The receiver's freshly-installed
`peerCrypto` had `maxRecvNonce = 0`; out-of-order arrival of nonces
1..32 tripped the replay-window check. 4 covers the realistic shape
(task submit + send-results + a couple of dataexchange retries)
without overwhelming the receiver. Memory drops from ~48 KiB / peer
to ~6 KiB; ~6 MiB worst-case fleet-wide at `maxCryptoPeers = 1024`.

### 4. Preserve nonce/replay state across duplicate key_exchange (`d4d5f42`)

The latent companion bug: `handleAuthKeyExchange` and
`handleKeyExchange` used to **unconditionally replace** `tm.crypto[N]`
with a freshly-derived `peerCrypto`, even when the peer's pubkey was
unchanged. Same shared secret, but reset nonce counter and empty
replay bitmap. Subsequent encrypted sends used counter 1, 2, 3...
while peer's `pc[us]` had a high `maxRecvNonce` from before, so
peer dropped them as "outside replay window."

Fix: replace only when there's no existing entry OR the pubkey
actually changed. Pinned by
`TestHandleKeyExchangeDuplicatePreservesCryptoState`.

(This same fix was attempted earlier in the session and reverted —
it was incompatible with the 32-entry salvage cap. After the cap
reduction in `5de736f`, the preservation fix is safe.)

## Tests added

- `pkg/daemon/tunnel_desync_salvage_test.go` — 7 unit tests for the
  ring buffer (size + age bounds, copy-not-reference, nil-safety).
- `pkg/daemon/tunnel_rekey_retransmit_test.go` — 9 unit tests for the
  retransmit state machine (mark, clear, stale, give-up cap).
- `pkg/daemon/tunnel_dup_keyexchange_test.go` — 2 unit tests pinning
  duplicate-preservation and real-rekey-replacement.
- `tests/integration/local/test_tunnel_desync_recovery.sh` — black-box
  test: establish tunnel, restart receiver, submit task immediately,
  assert it lands within 30 s.

## Verified

| Test | Result |
|---|---|
| `go vet ./...` | clean |
| `go test -parallel 4 ./pkg/... ./tests/` | all 10 packages pass |
| `test_tunnel_desync_recovery` | 7/0 |
| `test_midrekey_send_file` | 5/0 (was 4/1, P1-009 repro) |
| `test_midrekey_send_message` | 6/0 (was 5/1, P1-009 repro) |
| `test_midrekey_task_results` | 6/0 (was 4/2, P1-009 repro) |
| `test_midrekey_task_submit` | 5/0 (was 3/2, P1-009 repro) |
| `test_peer_restarted_send_file` | 4/0 (was 3/1) |
| `test_peer_restarted_send_message` | 5/0 (was 3/2) |
| `test_sender_clean_restart_midflight` | 6/0 |
| `test_chaos_packet_loss` | 9/0 |
| `test_force_relay_task` | 4/0 |
| Full integration suite (`btjsk44z8`, -j 8) | 225/232 — best of cycle |

## Other (pre-RC2 but post-RC1) work folded in

- `b4237e3` + `71e5f56` — 30 open-data network blueprints (academic,
  geo, health, news, finance, etc.). Already deployed to production
  registry as IDs 44–73. Open-join, default-allow, full inter-agent
  communication.
- `e7d9efb` — untracked runtime artifacts that should never have been
  committed (test logs, results); added matching `.gitignore` rules.
- `aa0cb6a`, `08b3a34`, `c843c4a`, `22092c3` — website / blog content,
  no protocol impact.

## Backwards compatibility

Wire-compatible with `v1.8.0` and `v1.9.0-rc1` daemons. No new packet
types, no new fields, no version negotiation. Mixed deployments are
safe. The retransmit loop and salvage replay are visible to peers as
ordinary key_exchange / encrypted frames respectively.

## Known limitations (unchanged from RC1)

- `test_cli` — env-gated (hits production `agent-alpha`).
- `test_register_identity_new_endpoint` — architectural (container
  PID-1 dies on `pkill`). Needs Dockerfile init wrapper.
- Vouching-chain transitive walk unimplemented.
- Trust links global, not per-network (design choice).
- `DefaultVerdict` policy field fails OPEN on pre-v1.9 daemons —
  upgrade daemons before pushing configs that rely on it.

## Upgrade

No coordinated rollout needed. Update daemons in any order:
rendezvous → agents is the recommended sequence purely for the
`DefaultVerdict` ordering risk. Old daemons keep working unchanged.

## Full commit log

```
d4d5f42 Preserve nonce/replay state across duplicate key_exchange
c843c4a Add blog post: AI agent discovery: master P2P networks in 2026
5de736f Cap desync salvage at 4 entries (was 32) to prevent replay storm
22092c3 Hero: decorative boids flock behind the headline
a126a26 P1-010 tunnel-state half: retransmit pending key exchanges
7f76e75 P1-010: salvage in-flight plaintext on peer-initiated rekey
08b3a34 Add blog post: Overlay networking: Secure AI agent communication explained
aa0cb6a Add blog post: Top 6 openanp.ai Alternatives 2026
71e5f56 Open-data networks: full inter-agent communication; SHIPPED roster
b4237e3 Add 30 open-data network blueprints
e7d9efb Untrack runtime artifacts that should never have been committed
```

`git log v1.9.0-rc1..v1.9.0-rc2 --oneline` (11 commits).
