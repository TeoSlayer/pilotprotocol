# Runbook — Pilot Protocol CA operations

**Audience:** operator with access to the offline root key custody hardware (Yubikey or air-gapped machine).
**Scope:** how to mint the production root CA, sign beacon leaf certs, rotate roots, and verify chains.
**Tool:** `cmd/pilot-ca` (`go run ./cmd/pilot-ca`).

## Current production status (2026-05-18)

**The Pilot CA is NOT yet in production use.** The compat-mode WSS endpoint at `beacon.pilotprotocol.network` currently uses a **Let's Encrypt** certificate, terminated by nginx on the rendezvous host. The daemon's `-tls-trust` default is `system`, which verifies against the OS trust store.

This runbook describes the future-hardening path: when we mint the production Pilot root, embed it in client binaries, and flip `-tls-trust=pinned` as the default, attacks that compromise a public CA can no longer MITM compat daemons. Until that release ships, the Pilot CA tooling below is rehearsal-only.

## The trust model in one paragraph

Every compat-mode daemon ships with the Pilot Protocol root CA cert embedded in its binary (via `//go:embed` from `internal/transport/compat/roots/*.pem`). When the daemon dials WSS to a beacon, it verifies the beacon's leaf cert chains to that embedded root and only that root. Public CA compromises (Let's Encrypt issuance bugs, DNS hijacks, etc.) cannot MITM compat daemons. The cost: the private root key must stay offline, and rotations require shipping a new daemon binary.

## What's currently embedded

`internal/transport/compat/roots/dev-2026.pem` — a development-only root used until the first production root is minted. **Replace before shipping compat mode to production.**

## Phase 1 — First-time production root setup

Do this on an air-gapped machine or a host with the root key on a Yubikey.

1. Build the tool:
   ```
   go build -o pilot-ca ./cmd/pilot-ca
   ```

2. Mint the root keypair + self-signed root cert:
   ```
   mkdir -p /secure/pilot-root-2026
   ./pilot-ca init-root /secure/pilot-root-2026
   ```
   This writes:
   - `/secure/pilot-root-2026/root.key` (mode 0600) — **the trust anchor. Move to offline storage immediately.**
   - `/secure/pilot-root-2026/root.crt` (mode 0644) — public cert; commit to repo.

3. Commit the root cert to the repo:
   ```
   cp /secure/pilot-root-2026/root.crt internal/transport/compat/roots/prod-2026.pem
   git add internal/transport/compat/roots/prod-2026.pem
   ```
   At this point the dev root (`dev-2026.pem`) can be deleted from `roots/` — daemons will now trust the production root. Keep `dev-2026.pem` only if you want the same daemon binary to trust both (useful during transition windows).

4. Move `root.key` to your custody hardware (Yubikey, hardware-encrypted USB, etc.). Wipe the source machine. **There must be exactly one copy of root.key, and it must not be on a network-attached host.**

## Phase 2 — Issuing a beacon leaf cert

Each beacon hostname needs its own leaf cert, signed by the root. Leaf certs are P-256 ECDSA, valid for 90 days, and should be auto-rotated before expiry.

On the offline host (or a host with the root key temporarily mounted from custody hardware):

```
mkdir -p /tmp/beacon-us
./pilot-ca issue-beacon /secure/pilot-root-2026 beacon-us.pilotprotocol.network /tmp/beacon-us
```

Output:
- `/tmp/beacon-us/beacon-us.pilotprotocol.network.key` (mode 0600) — TLS private key for the beacon
- `/tmp/beacon-us/beacon-us.pilotprotocol.network.crt` (mode 0644) — leaf cert chained to root

Deploy both files to the beacon VM via secure channel (scp, encrypted artifact, etc.). The Caddy front-end (or beacon's in-process TLS, depending on Phase 4 of SPEC) loads them from disk and serves them on port 443.

After deploy, unmount the root key from this host.

## Phase 3 — Verifying a deployed chain

Before flipping traffic to a new beacon, confirm the leaf cert actually chains to the embedded root:

```
./pilot-ca verify internal/transport/compat/roots/prod-2026.pem /tmp/beacon-us/beacon-us.pilotprotocol.network.crt
```

Expected output:
```
OK — beacon-us.pilotprotocol.network.crt chains to prod-2026.pem
  CN=beacon-us.pilotprotocol.network  not-after=2026-08-17T00:32:14Z
```

Any other output = abort the deploy. Common failures:
- `verify failed: x509: certificate signed by unknown authority` — the leaf was signed by a different root than the one in `roots/`. Either re-issue against the correct root or update the embedded root.
- `verify failed: x509: certificate has expired or is not yet valid` — wall-clock or cert dates are wrong; re-issue.

## Phase 4 — Leaf rotation (every 75 days)

Leaf certs expire after 90 days. Re-issue at day 75 so there's a 15-day overlap window:

```
./pilot-ca issue-beacon /secure/pilot-root-2026 beacon-us.pilotprotocol.network /tmp/beacon-us-fresh
./pilot-ca verify internal/transport/compat/roots/prod-2026.pem /tmp/beacon-us-fresh/beacon-us.pilotprotocol.network.crt
# scp the .key and .crt to the beacon, atomically replace, send SIGHUP to Caddy (it reloads).
```

Daemons don't notice — TLS sessions in flight stay valid; new connections use the new cert.

Automation candidate: drive this from a periodic cron on the custody host, since the root key has to be online briefly. Out of scope for v1 — manual ops is fine while we have one or two beacons.

## Phase 5 — Root rotation (every 5-10 years, or after compromise)

Multi-release event. The procedure:

1. **Day 0:** Mint new root (`prod-2031.pem`). Commit it to `internal/transport/compat/roots/` *alongside* the old root. The daemon binary now trusts BOTH roots.
2. **Day 0+N (N = enough time for daemon fleet to update):** Issue new leaf certs signed by the new root; deploy to beacons. New connections from updated daemons verify against the new root.
3. **Day 90+:** Remove the old root from `roots/`. Old daemon binaries that haven't updated lose connectivity — they get the explicit `WARN: TLS verification failed; -tls-trust=system might be needed` and the operator decides whether to upgrade them or unblock with the fallback flag.

For a compromise-driven rotation, compress the window aggressively — flip to the new root immediately, push an emergency daemon upgrade, and document the incident.

## Failure modes to plan for

- **Lost root key.** Cannot issue new leaf certs. As leaves expire (~90 days), all beacons go dark for compat mode. Mitigation: keep a second copy of root.key in a separate custody location (operationally important but creates a second exfil risk to manage).
- **Compromised root key.** Attacker can mint beacon certs and MITM compat daemons. Mitigation: immediate rotation per Phase 5 + emergency daemon upgrade.
- **Embedded root accidentally deleted from `roots/`** in a refactor. `TestPinnedRoots_LoadsEmbeddedRoots` fails loudly in CI — the build cannot ship with zero embedded roots.
- **Build cache stale, daemon ships with old root cert.** Force `go build -trimpath` and re-verify with `pilot-ca verify`.

## Files an operator touches

| Path | Mode | Who | Where |
|---|---|---|---|
| `cmd/pilot-ca/main.go` | source | engineers | repo |
| `internal/transport/compat/roots/*.pem` | 0644 | engineers | repo (public) |
| `/secure/.../root.key` | 0600 | operator (sole custody) | offline / Yubikey |
| `/secure/.../root.crt` | 0644 | operator | offline (matches repo copy) |
| `/etc/pilot/beacon/<host>.key` | 0600 | beacon host | beacon VM only |
| `/etc/pilot/beacon/<host>.crt` | 0644 | beacon host | beacon VM only |

## What the tool deliberately does NOT do

- No automatic OCSP / CRL stapling. Compat mode is a small, controlled PKI — short-lived leaves + fast embed rotation are simpler than CRL distribution.
- No ACME. ACME requires DNS or HTTP control of the validated domain, which exposes a public DNS/HTTP attack surface we don't otherwise need. Manual `pilot-ca issue-beacon` is the right granularity until we have hundreds of beacons.
- No HSM integration in the binary. The operator's custody is whatever they choose (Yubikey via OpenSSL engine, GPG smartcard, air-gapped Linux). `pilot-ca init-root` writes a software key; the operator is responsible for moving it.
