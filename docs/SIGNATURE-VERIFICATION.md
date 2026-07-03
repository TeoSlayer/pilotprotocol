# External Signature Verification

Status: implemented (registry endpoint, daemon IPC, app-store capability)

This document specifies how a service — on or off the Pilot network — can
verify that a request originates from a registered Pilot node, that the
signature was made by that node's registered key (not an arbitrary ed25519
key), and whether the node is currently online and in good standing. It also
specifies the per-node rate-limiting capability this enables for apps.

Three exposure surfaces share one envelope format:

| Surface | Consumer | Package / endpoint |
|---|---|---|
| Registry HTTPS oracle | off-network web services | `POST /api/v1/verify` on the registry dashboard |
| Daemon IPC | processes on a Pilot host, incl. store apps | `CmdSignEnvelope` (0x33), `CmdVerifyEnvelope` (0x35) |
| Offline verdict check | anyone holding a verdict | `common/reqsig.VerifyVerdict*` |

## 1. Request envelope (`common/reqsig`)

A node proves "this request, from me, for you, now" by signing the canonical
envelope string:

```
pilot-req-v1|aaaaaaaaaaaa|ts|nnnnnnnnnnnnnnnn|hhhh…64…hhhh|audience
```

- `aaaa…` — 12 lowercase hex chars: 16-bit network + 32-bit node ID. The
  text address format (`N:NNNN.HHHH.LLLL`) is never used inside the envelope
  because it contains delimiter characters.
- `ts` — canonical decimal unix seconds.
- `nonce` — 16 lowercase hex chars (8 random bytes).
- `body hash` — sha256 hex of the request body (the body itself never
  travels to a verifier).
- `audience` — the consuming service's identifier, `[a-z0-9.-]{1,64}`.
  Binds the signature to one recipient so it cannot be replayed to another.

Every field has a fixed charset that excludes `|`, so the encoding is
unambiguous. Parsers reject non-canonical encodings bit-for-bit.

**Freshness.** Verifiers reject envelopes outside a ±300 s window
(`reqsig.DefaultMaxSkew` — generous deliberately: the fleet includes embedded
devices with real clock skew). Nonce deduplication within the window is the
consuming service's responsibility; verifiers echo the nonce so services can
key a dedup cache on it.

**Domain separation.** The `pilot-req-v1` prefix ensures an envelope
signature can never be confused with protocol-internal signatures
(heartbeats, key exchange, badges) — and vice versa: a signature captured off
the wire never verifies as an envelope.

## 2. Registry endpoint

`POST /api/v1/verify` on the registry dashboard (HTTPS is terminated at the
edge; the endpoint must not be exposed without it).

Request: `{"envelope": "<canonical>", "signature": "<base64>"}` (body capped
at 8 KB). Response:

```json
{
  "valid": true,
  "online": true,
  "network_member": true,
  "address": "1:0001.ABCD.1234",
  "last_seen": "2026-07-03T09:00:00Z",
  "last_seen_unix": 1782205200,
  "key_generation": 3,
  "stale_threshold_secs": 1800,
  "nonce": "0123456789abcdef",
  "verdict": "pilot-verdict-v1|…",
  "verdict_sig": "<base64>",
  "verdict_kid": "vfy-v1"
}
```

Semantics:

- `valid` — the signature verifies against the **registered, unexpired** key
  for the node named in the envelope, and the envelope is fresh. A key that
  was never registered has no address binding, so "random ed25519 key"
  fails structurally.
- `online` — the node's last signature-verified heartbeat is within **180 s**
  (three missed 60 s heartbeats). This is *standing*, not reachability: the
  node is registered, heartbeating, unexpired, not reaped. Note the
  registry's heartbeat path skips re-verification for 120 s after a verified
  heartbeat, so a dead node can appear online for at most ~5 minutes.
- `network_member` — the node is a member of the network named in the
  envelope's address prefix. Key binding is per-node; the network half is
  membership, reported separately.
- Nodes offline longer than the stale threshold (default 30 min) are reaped
  and become **unverifiable** (`valid: false`) until they re-register. Dead
  identities stop authenticating by design.

**Uniform failure.** Unknown node, reaped node, bad signature, stale
timestamp, and expired key all return the same `{"valid": false}` shape.
The endpoint is not an existence oracle over the address space.

**Abuse controls.** Per-IP rate limit (60 req/min), `dashboard.verify`
breaker (operators can kill the endpoint during incidents), POST-only,
size-capped body.

`GET /api/v1/verify/keys` returns the verdict issuer keys:
`{"keys":[{"kid":"vfy-v1","algo":"ed25519","public_key":"<base64>"}]}`.

## 3. Signed verdicts

The registry signs its answer so consumers can cache it, forward it as
proof, or check it offline:

```
pilot-verdict-v1|envhash|aaaaaaaaaaaa|v|o|m|last_seen|keygen|verified_at
```

`envhash` binds the verdict to the exact envelope verified. The issuer key is
held by the registry (auto-generated, persisted next to the registry
snapshot; KMS custody is the planned upgrade) and published at
`/api/v1/verify/keys`. Consumers verify with
`reqsig.VerifyVerdictWithKey`, or `reqsig.VerifyVerdict(kid, …)` when a
keyring is baked at build time via
`-ldflags "-X github.com/pilot-protocol/common/reqsig.verdictKeyringB64=vfy-v1=<b64>"`.
Negative verdicts are signed too.

## 4. Daemon IPC

Two commands (mirrored in `common/driver`):

**`CmdSignEnvelope` (0x33)** — mint an envelope. Payload
`{"audience": "...", "body_hash": "<64 hex>"}` (or `body_b64`; nonce
optional). The daemon **constructs the envelope itself** — its own address,
its own clock — and signs only that. There is no code path that signs a
caller-supplied string. This restriction is the security boundary, because
the daemon socket admits any same-UID process: a hostile local process must
not be able to obtain a node signature over a heartbeat, key-rotation
payload, another node's request, or any other protocol-internal message.

**`CmdVerifyEnvelope` (0x35)** — verify one. Payload
`{"envelope": "...", "signature": "...", "check_standing": bool,
"max_skew_secs": n}`. Key resolution is **local-first**: the key-exchange
peer-key cache (populated during authenticated handshakes), falling back to
a registry lookup on miss. `verified_via` reports which. `trusted` reports
handshake-trust-store membership. With `check_standing`, a registry lookup
adds `online` / `last_seen_unix` / `key_generation` / `network_member` when
the registry provides them. Verification of already-known peers never
touches the registry.

pilotctl front-ends: `pilotctl sign-request --audience <a> --body-file <f>`
and `pilotctl verify-request --envelope … --signature … [--standing]`.

## 5. App-store capability

Apps get verified sender identity two ways (`app-store` module):

**Daemon-attested origin.** Brokered IPC envelopes carry an optional
`origin` block — `{node, node_id, authenticated, trusted}` — set only by the
trusted daemon bridge (`Service.CallWithOrigin`). The broker strips any
origin supplied by an app on cross-app calls, so apps cannot forge it
through the broker. Trust boundary: a same-UID process dialing `app.sock`
directly can forge anything; same-UID is the platform trust boundary until
OS sandboxing lands.

**`pkg/appkit`.** Stdlib-only helpers:

```go
limiter := appkit.PerNodeLimiter(100, time.Minute)
d.Register("myapp.query",
    appkit.RequireOrigin(appkit.LimitPerNode(limiter, handler)))
```

- `RequireOrigin` — rejects requests without an authenticated origin.
- `LimitPerNode` — sliding-window rate limit keyed on the **verified node
  identity** (transport addresses are meaningless here: relayed traffic
  makes unrelated nodes share endpoints).
- `RequireEnvelope(verify, next)` — for out-of-band traffic (e.g. an app's
  HTTPS backend): extracts `pilot_envelope` / `pilot_signature` from the
  request payload, verifies via an injected `VerifyFunc` (wire it to
  `driver.VerifyEnvelope`), synthesizes the origin on success.

The `identity.verify` manifest capability declares that an app calls the
daemon's verification IPC (declarative/consent, like the rest of the grant
model).

**Sybil note.** Per-node limiting is per-*identity* limiting. It stops one
node hammering a service; it does not stop someone registering many
identities. Under Sybil pressure, incorporate standing signals already
carried in the origin/verdict (trusted, network_member, badge status) into
the limiter key or quota.

## 6. Threat model summary

| Threat | Mitigation |
|---|---|
| Signature from unregistered key | address→registered-key lookup; nothing to look up |
| Replay of a captured request | timestamp window + audience binding + consumer nonce dedup |
| Cross-service replay | `audience` field in the signed envelope |
| Cross-protocol signature confusion | `pilot-req-v1` domain separation both directions |
| Address-space enumeration via the endpoint | uniform `valid:false`; per-IP rate limit |
| Local process abusing node key via IPC | CmdSignEnvelope constructs+signs only well-formed envelopes for its own address |
| Origin forgery through the broker | broker strips caller-supplied origin |
| Dead node appearing alive | 180 s online window; ≤~5 min worst case (documented) |
| Verdict tampering / transport trust | ed25519-signed verdicts, offline-checkable, negatives signed too |
| Registry endpoint abuse | rate limit + breaker + body cap + POST-only |

## 7. Operational notes

- The verdict key is generated on first start and persisted (0600) next to
  the registry snapshot. Rotation = new kid + republish at
  `/api/v1/verify/keys`; migrate custody to KMS alongside the badge key.
- `stale_threshold_secs` and `last_seen` are returned so consumers can apply
  stricter freshness than the default `online` window.
- The `online` definition (180 s) is intentionally decoupled from the
  reaper's stale threshold (30 min); do not conflate them — any node still
  in the map is trivially within the reaper threshold.
