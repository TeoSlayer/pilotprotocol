# Proposal: Make TLS + key-pinning the default daemon→registry transport (H1)

Status: DRAFT — staged rollout design, not yet approved. No default flip is included.
Audit finding: H1 — the `node_id → public_key` mapping that all peer-handshake
authentication (and badge/recovery trust) rests on is fetched over plaintext TCP
by default. TLS + pinning exists but is opt-in.

This document is a design only. It changes no current default behaviour. Any
default flip is gated on the maintainer decisions in §7.

---

## 1. Current state (verified in code + against prod)

### 1.1 The trust that rests on the mapping

A receiving daemon authenticates an inbound key-exchange by fetching the peer's
expected Ed25519 public key from the registry and comparing it to the key carried
in the handshake packet:

- `pkg/daemon/keyexchange/handle.go:46-75` — `HandleAuthFrame` calls
  `GetPeerPubKey(peerNodeID)` *first*, rejects if unavailable, and verifies the
  packet-carried Ed25519 key + signature against the registry-returned key. This
  is the actual MITM surface: whoever controls the `node_id → pubkey` answer
  controls which key is "trusted".
- `pkg/daemon/keyexchange/keyexchange.go:382-407` — `GetPeerPubKey` resolves a
  cache miss through `verifyFunc`.
- `pkg/daemon/daemon.go:994` — `verifyFunc` is wired to `d.lookupPeerPubKey`.
- `pkg/daemon/daemon.go:5674-5686` — `lookupPeerPubKey` calls
  `d.regConn.Lookup(nodeID)` and reads `resp["public_key"]`.

So the entire peer-auth chain terminates at one registry lookup over `d.regConn`.

### 1.2 The lookup is application-layer-unauthenticated

The registry's lookup response is **not signed**. `EncodeLookupResp`
(`common/registry/wire/wire.go:183`) emits
`[node_id][flags][reserved][nets][pubkey_len][pubkey]...` with no registry
signature over the pubkey. The lookup *request* (`EncodeLookupReq`,
`wire.go:168`) is `[4B node_id]` — also unauthenticated. Integrity of the pubkey
therefore depends **entirely on the transport**. There is no second line of
defence at the application layer.

### 1.3 The transport is plaintext by default

Daemon (`cmd/daemon/main.go`):

- `-registry` default `34.71.57.205:9000` (`registryDefault`, line ~46).
- `-registry-tls` default **`false`** (line 65).
- `-registry-trust` default `"pinned"` (line 67) — but only consulted when
  `-registry-tls` is set.
- `-registry-fingerprint` default `""` (line 66).

Dial selection (`pkg/daemon/daemon.go:888-912`):

```
if RegistryTLS:
    trust=="pinned" -> registry.DialTLSPinned(addr, fingerprint)   // needs fingerprint
    trust=="system" -> registry.DialTLSPool(addr, {MinVersion:TLS12}, 4)
else:
    registry.DialPool(addr, 4)                                     // PLAINTEXT — default
```

Because `-registry-tls` defaults to false, **the default path is
`registry.DialPool` = plaintext TCP** (`common/registry/client/client.go:150`).

`pilotctl` is worse: it has **no TLS option at all**. `connectRegistry()`
(`cmd/pilotctl/main.go:487`) and the badge/recovery path
(`cmd/pilotctl/verify.go:301`, `RecoverIdentity`) both call `registry.Dial(addr)`
(plaintext) against `34.71.57.205:9000`. Recovery — re-binding a node_id to a new
key — runs over plaintext.

The compat tunnel mode (`-transport=compat`) does auto-route the registry to
`registry.pilotprotocol.network:443` with `system` trust
(`cmd/daemon/main.go:158-173`), but that is opt-in and only for UDP-blocked
environments — the 222K-node default fleet is on `:9000` plaintext.

### 1.4 What "pinning" means here

`DialTLSPinned` (`common/registry/client/client.go:239-258`):
`InsecureSkipVerify: true` + `VerifyPeerCertificate` comparing the **SHA-256 of
the server's DER-encoded leaf certificate** to a hex fingerprint. This is a
**leaf-cert pin**, not an SPKI pin and not a registry-pubkey pin. Consequence:
it breaks the moment the registry's leaf cert rotates (including Let's Encrypt's
~60-day renewals). Pinning the SPKI (public-key info) instead would survive
same-key renewals.

### 1.5 What the registry actually serves (verified against prod 2026-06)

- `34.71.57.205:9000` → **plaintext** (raw TCP; TLS handshake fails). Matches the
  prod log line `registry listening transport=plaintext`. Server default
  `-tls=false` (`rendezvous/cmd/rendezvous/main.go:68`,
  `accept/accept.go:662-669`).
- `registry.pilotprotocol.network:443` → **valid Let's Encrypt cert**
  (CN=registry.pilotprotocol.network, ECDSA via E7 intermediate, ~90-day cert,
  renewed ~every 60 days). Fronted by Caddy/nginx terminating TLS; the Go binary
  speaks plain WS/TCP upstream (`-wss-addr`, `main.go:80`).

So a publicly-trusted TLS endpoint **already exists** and works today — it is
just not the default the fleet dials, and `system` trust (CA chain) is weaker
than a pin against a network-controlled identity.

### 1.6 Self-signed instability (why naïve pinning is fragile)

`accept.SetTLS("","")` → `GenerateSelfSignedCert()` produces an **in-memory**
cert regenerated on every server restart (`accept/accept.go:419,632`). Pinning a
leaf fingerprint against an auto-self-signed registry would break every pinned
client on each registry restart. A pinned deployment therefore **requires a
persistent cert/key on disk** (`-tls-cert`/`-tls-key`) with a stable identity.

---

## 2. Target state

The `node_id → pubkey` answer must be authenticated against a **network-controlled
identity that clients verify without trusting a public CA** and without a
first-contact TOFU window.

Two complementary mechanisms; we want **both**, but only (A) is required to close
H1 at the transport layer:

**(A) Pinned TLS to the registry, by default.** Daemon (and eventually pilotctl)
dial the registry over TLS and verify the server identity against a pin that
ships in the binary, not the OS trust store. Pin against the **SPKI** of a stable
registry key (Pilot-controlled), surviving cert renewals. Maintain a small set of
valid pins (current + next) to allow key rotation.

**(B) Application-layer signing of the lookup response (defence in depth).** The
registry signs `(node_id, pubkey, ...)` with a Pilot registry signing key whose
public half ships in the binary; clients verify the signature on every lookup.
This makes the `node_id → pubkey` mapping authenticated **independent of
transport**, so a future TLS-terminating proxy, a mis-pinned client, or a
compromised CA cannot forge the mapping. (B) is a wire-format change in
`common/registry` and is the durable fix; (A) is the faster one. Recommend
shipping (A) first, (B) as a fast-follow.

Plaintext `:9000` is ultimately retired (or kept only as an explicitly-flagged,
loudly-warned escape hatch).

---

## 3. Staged migration (never breaks live nodes)

Guiding rule: **clients learn to prefer the secure path before the server removes
the insecure one, and the server offers the secure path before clients require
it.** No stage makes a previously-working daemon fail.

### Stage 0 — Pin distribution & stable server identity (server + build, no client behaviour change)

This solves the pin-distribution / TOFU problem *before* any client prefers TLS.

1. Generate a long-lived registry TLS identity (dedicated keypair, not the
   Let's Encrypt leaf) and persist it. Serve it on a TLS listener on `:9000`'s
   sibling port (e.g. `:9443`) via `-tls -tls-cert -tls-key`, **in addition to**
   plaintext `:9000`. Keep `:443` (Let's Encrypt) as-is for compat/system trust.
2. **Bake the pin into the release.** The SPKI pin (and the registry signing
   pubkey for Stage B) are embedded as compiled constants in the daemon/pilotctl
   binaries — same model already used for `internal/transport/compat/roots.go`
   (the embedded Pilot CA root) and `internal/trustedagents`. Because the pin
   ships *in the signed binary the auto-updater already distributes*, there is
   **no TOFU first-contact window**: the client knows the expected identity
   before it ever connects.
3. Also publish the pin out-of-band for verification: in the pinned catalogue,
   on the website Configuration page, and in release notes — so operators can
   audit that the embedded pin matches.
4. Switch SPKI-pin support into `DialTLSPinned` (today it is a leaf-cert pin):
   add an SPKI-fingerprint comparison path so renewals don't break pins.

Compatibility: zero. No client dials the new listener yet. Rollback: stop serving
the extra listener.

### Stage 1 — Ship clients that CAN pin, opt-in (client release N)

1. Add embedded-pin support to the daemon: a `-registry-trust=pinned-builtin`
   value (or `RegistryFingerprint`/SPKI auto-populated from the embedded
   constant when empty) so an operator can select pinned TLS **without manually
   copying a fingerprint**.
2. Add the same TLS+pin capability to `pilotctl` (currently has none): a
   `--registry-tls`/built-in-pin path through `connectRegistry()` and the
   recovery/verify dial in `verify.go`.
3. Default remains plaintext. Operators opt in. Document it.

Compatibility: zero default change. Older daemons unaffected. Rollback: operators
drop the flag.

### Stage 2 — Prefer-TLS-with-fallback + adoption telemetry (client release N+1)

1. Default behaviour becomes: **try pinned TLS first; on dial/handshake failure,
   fall back to plaintext with a loud WARN** (`slog.Warn("registry: falling back
   to PLAINTEXT — MITM-exposed; …")`). This makes the secure path the *preferred*
   path while guaranteeing no daemon loses connectivity if the TLS listener is
   unreachable for it.
2. Emit consent-gated telemetry recording which transport each daemon actually
   used (pinned-tls / system-tls / plaintext-fallback). Wire through the existing
   `pkg/telemetry` client (the same consent-gated path used elsewhere) so we can
   measure TLS adoption across the fleet.
3. The fallback is the safety net that lets us change the default without a flag
   day; the telemetry is what tells us when fallback has stopped firing.

Compatibility: a daemon whose network blocks the TLS port keeps working via
fallback (with warnings). Rollback: revert the default to plaintext-first; the
code paths already exist.

### Stage 3 — Flip the default to pinned-TLS-required-with-warned-fallback (client release N+2)

Precondition: Stage-2 telemetry shows TLS success ≥ an agreed threshold
(e.g. ≥99% of active daemons reaching the TLS listener) **and** the registry has
served the pinned listener stably for ≥1 renewal cycle.

1. Default `-registry-tls=true`, `-registry-trust=pinned-builtin`.
2. Fallback to plaintext **still exists** but now requires an explicit
   `-registry-allow-plaintext` opt-out flag (loud warning), so a default flip
   can never strand a daemon — the operator can always re-enable plaintext.
3. The auto-updater rolls release N+2 across the fleet gradually (it already
   checks GitHub releases hourly and is opt-in per host — see §4).

Compatibility: daemons that genuinely can't reach the TLS listener fail closed by
default but have a documented escape hatch. Rollback: ship N+2.1 reverting the
default; or operators set `-registry-allow-plaintext`.

### Stage 4 — Deprecate, then disable plaintext (server, release N+3+)

1. Server logs every plaintext accept with the connecting node_id (deprecation
   signal); dashboards surface remaining plaintext talkers.
2. Once the plaintext-talker count is ~0 for a sustained window, drop the
   plaintext `:9000` listener (or gate it behind a server `-allow-plaintext`
   flag, default off).

Compatibility: only daemons still on plaintext break — by then a measured ~0.
Rollback: re-enable the plaintext listener (one flag).

---

## 4. Compatibility analysis — the 222K fleet + auto-updater

- **Auto-updater is opt-in and per-host** (writes `~/.pilot/auto-update.json`,
  re-read each tick; controlled via `pilotctl update enable|disable`). It checks
  GitHub releases hourly. This means **the fleet does not update atomically** —
  at any moment a mix of release N, N-1, N-2 is live. Every stage must tolerate
  version skew, which the prefer-with-fallback design (Stage 2) and the
  server-offers-before-client-requires ordering (Stage 0 before Stage 3)
  guarantee.
- Hosts with auto-update **off** stay on old releases indefinitely. They keep
  working as long as plaintext `:9000` is served — which is why Stage 4
  (disable plaintext) is gated on observed ~0 plaintext talkers, not on a date.
- **Per-stage break matrix:**
  - Stage 0: nothing breaks.
  - Stage 1: nothing breaks (opt-in).
  - Stage 2: nothing breaks; daemons on TLS-blocked networks fall back + warn.
  - Stage 3: daemons that can't reach TLS **and** can't get the new release
    would fail closed — mitigated by the `-registry-allow-plaintext` escape hatch
    and by not flipping until telemetry shows ~full reachability.
  - Stage 4: only still-plaintext daemons break (by then ~0).
- **pilotctl** is a separate binary (Homebrew tap + install.sh). Its TLS path
  (Stage 1) and default flip should track the daemon's but can lag; until then
  recovery/verify stay plaintext, so **prioritise pilotctl pinning** given
  recovery is the highest-value target.

---

## 5. Concrete code touch-points

Stage 0 (server + build):
- `rendezvous/cmd/rendezvous/main.go` — run a second TLS listener with a
  persistent cert (`-tls -tls-cert -tls-key`) alongside plaintext; deploy a
  stable registry keypair.
- `rendezvous/accept/accept.go:604-654` — ensure a stable on-disk cert path
  (avoid the in-memory self-signed regen for the pinned listener).
- `common/registry/client/client.go:239-258` — add an **SPKI** pin comparison
  alongside the existing leaf-cert fingerprint pin.
- New embedded constant (mirror `internal/transport/compat/roots.go`): registry
  SPKI pin(s) + (Stage B) registry signing pubkey.

Stage 1 (clients can pin):
- `cmd/daemon/main.go:65-67,226-228` — add `pinned-builtin` trust mode; populate
  `RegistryFingerprint`/SPKI from the embedded constant when empty.
- `pkg/daemon/daemon.go:888-912` — dial selection: add the builtin-pin branch.
- `cmd/pilotctl/main.go:264-272,487-495` — add TLS+pin to `getRegistry`/
  `connectRegistry`.
- `cmd/pilotctl/verify.go:301` (and `RecoverIdentity` path) — TLS+pin the
  recovery dial.

Stage 2 (prefer + telemetry):
- `pkg/daemon/daemon.go:888-926` — wrap the dial loop: try pinned TLS, fall back
  to plaintext with WARN; record the chosen transport.
- `pkg/telemetry/client.go` — add a transport-adoption metric (consent-gated).

Stage 3 (flip):
- `cmd/daemon/main.go` — defaults `-registry-tls=true`,
  `-registry-trust=pinned-builtin`; add `-registry-allow-plaintext`.

Stage 4 (server retire):
- `rendezvous/cmd/rendezvous/main.go` / `accept/accept.go` — log/gate plaintext
  accepts; later drop the plaintext listener.

Stage B (defence in depth, any time after Stage 0):
- `common/registry/wire/wire.go:183` (`EncodeLookupResp`) + client decode — add a
  registry signature over `(node_id, pubkey, …)`; verify in
  `pkg/daemon/daemon.go:5674-5686` (`lookupPeerPubKey`).

---

## 6. Pin-distribution problem (explicit)

The classic objection to pinning is the bootstrap: how does a client learn the
pin without a TOFU window an attacker can occupy? Resolution here:

- The pin is **compiled into the binary** the auto-updater already ships and that
  install.sh/Homebrew already distribute — the same trust path already used for
  the embedded compat CA root and trusted-agents list. The client knows the
  expected registry identity *before first connect*. **No TOFU.**
- The binary's own integrity is the root of trust (release signing + the
  updater's existing verification). We are not adding a new trust anchor, we are
  reusing the one that already gates code execution.
- We pin **SPKI** (stable across renewals) and carry **multiple valid pins**
  (current + next) so the registry key can be rotated by shipping a release that
  adds the next pin before the server switches to it.
- The pin is also published out-of-band (catalogue, website, release notes) for
  auditability.

---

## 7. Risks & open questions (maintainer decisions needed before any flip)

1. **SPKI vs leaf-cert pin.** Confirm we move `DialTLSPinned` to SPKI pinning
   (recommended) so Let's Encrypt / cert renewals don't break pins. The current
   leaf-cert pin would require re-pinning every ~60 days.
2. **Registry TLS identity.** Do we mint a dedicated long-lived Pilot registry
   keypair for pinning (recommended), or pin the SPKI of the existing Let's
   Encrypt-fronted endpoint? The latter couples the pin to ACME key rotation.
3. **Port topology.** Serve pinned TLS on `:9000` itself (protocol-sniff or flag
   day on the port) or on a new sibling port (e.g. `:9443`)? Sibling port is
   non-breaking; reusing `:9000` is cleaner long-term but needs care.
4. **Stage B scope.** Do we also ship application-layer signed lookups (the
   transport-independent fix)? Recommended, but it is a `common/registry`
   wire-format change with its own compat story.
5. **Adoption threshold for the Stage-3 flip.** What TLS-reachability % and what
   soak time gate the default flip?
6. **pilotctl priority.** Recovery/verify over plaintext is arguably the
   single highest-value target. Confirm we fast-track pilotctl pinning ahead of
   the daemon default flip.
7. **Escape hatch policy.** Keep `-registry-allow-plaintext` indefinitely
   (operability) or sunset it on a date (security)?

No code in this proposal changes a default. Approval of the above unblocks
Stage 0 (server-side, fully backward-compatible) as the first concrete step.
