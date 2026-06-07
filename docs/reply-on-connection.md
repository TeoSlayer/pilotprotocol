# Reply-on-connection

Reply-on-connection lets a **directory/service agent answer on the same
connection the requester opened**, instead of dialing the requester back to
deliver the reply. It exists so a requester that is unreachable for an inbound
dial — behind NAT, no public port, or a short-lived client — can still receive
the answer, with no `--wait` and no dial-back.

> **`--auto-answer` is a specialised flag for service/directory agents only
> (e.g. `list-agents`). Regular nodes must never set it.** A normal node has no
> reason to hold a connection open to generate a reply; setting it on an
> ordinary node is incorrect and unsupported.

## How it works

```
 REQUESTER (any node, even NAT'd / transient)        SERVICE AGENT (--auto-answer)
 send-message <agent> --data '/data {…}' --reply-on-conn
   │  sends a TypeAutoAnswer frame ─────────────────▶ accepts on port 1001
   │                                                  TypeAutoAnswer → does NOT save to inbox
   │                                                  → GET <responder>/dispatch?message=…
   │                                                       (responder: classify → cache → fetch)
   │  ◀── ACK "ACK+REPLY …" ─────────────────────────  writes ACK (marked)
   │  ◀── reply (the answer) on the SAME connection ─  writes reply, then graceful close
   │  reads reply → ~/.pilot/inbox/, then closes
   ✅ answer is in the requester's inbox — no dial-back
```

Exactly **one request + one reply**, then the connection closes — there is no
loop, so two `--auto-answer` peers cannot ping-pong.

## Requester side — `send-message --reply-on-conn`

```bash
pilotctl send-message list-agents --data '/data {"search":"weather"}' --reply-on-conn
# reply is written to ~/.pilot/inbox/ as a normal message (read it with: pilotctl inbox)
```

- Sends the request as a `TypeAutoAnswer` frame and reads the reply off the
  connection into `~/.pilot/inbox/` — same JSON shape as a dial-back reply.
- No `--wait` needed; the reply arrives on the connection the requester opened.
- **Always safe — never worse than a plain send.** Against an `--auto-answer`
  agent the reply rides back on the connection (so it works even when the sender
  is NAT'd, has no public port, or is transient). Against **any other agent** the
  client transparently falls back to a normal dial-back: an updated agent saved
  the request; an old/stock agent — which acks the frame as `UNKNOWN` — triggers
  an automatic resend as plain `TEXT`. Either way the reply is dial-backed just
  like a normal send. Env: `PILOT_REPLY_ON_CONN=1`.
- Requires an updated `pilotctl`/SDK. A stock `pilotctl` (no flag) behaves
  exactly as before and is unaffected.

> **How the fallback works.** A `--reply-on-conn` sender looks at the ack: an
> `ACK+REPLY` reads the reply on the connection; an ack naming the `AUTOANSWER`
> type means an updated agent saved it for dial-back; anything else means an old
> agent didn't understand it, so the sender resends as plain `TEXT`. The benefit
> (no dial-back) is realised only against `--auto-answer` agents, but the flag is
> safe to set against anyone.

## Service-agent side — `--auto-answer` + responder `--serve-addr`

Two processes on the service-agent host:

```bash
# responder: keep the inbox→dial-back loop for current senders, AND expose its
# real dispatch (classify + loop-prevention + cache + fetch) over HTTP.
responder-go --endpoints …/endpoints.yaml --inbox-dir …/inbox \
             --serve-addr 127.0.0.1:18200        # env: RESPONDER_SERVE_ADDR

# daemon: answer opted-in requests on-connection via the responder's /dispatch.
pilot-daemon … --auto-answer http://127.0.0.1:18200/dispatch
```

- `--auto-answer` must point at the **responder's `/dispatch`**, not the raw
  agent service — so the reply uses the responder's real logic, including
  **loop-prevention** (prose and envelope-reply inputs are dropped, never
  forwarded) and the response cache.
- The daemon's normal data-exchange path (port 1001 → inbox) is **unchanged**.
  Plain `TypeText`/`TypeJSON` requests from current senders are served exactly as
  before. The auto-answer loop runs *only* for `TypeAutoAnswer` requests. This is
  why `--auto-answer` can be enabled on a live directory agent **without
  disturbing current traffic** — and why it is safe to test incrementally.

## Compatibility matrix

| Requester ↓ / Agent → | old/stock daemon | updated daemon (plain) | updated + `--auto-answer` |
|---|---|---|---|
| stock `pilotctl` | dial-back (as today) | dial-back | dial-back |
| `--reply-on-conn` | dial-back (auto-resend as TEXT) | dial-back (saved) | **reply-on-connection** ✅ |

`--reply-on-conn` always delivers a reply — it falls back to dial-back against
any non-`--auto-answer` agent. The new on-connection benefit (no dial-back, works
when the sender is unreachable) is gained only against `--auto-answer` agents, so
roll the daemon out to receivers to extend that benefit; the flag is safe to use
before then.

## Semantics & flag interactions

- **At-least-once dispatch.** If an on-connection reply is lost in flight (relay
  hiccup) or the agent exceeds the window, the client resends as plain TEXT to
  guarantee delivery — which can cause the agent to process the request **twice**.
  This is fine for the read-only directory/specialist queries reply-on-connection
  is meant for; do not use it for non-idempotent requests.
- **Timeout chain (strictly increasing).** responder fetch `35s` < daemon
  `--auto-answer` HTTP `38s` < service `autoAnswerWindow` `40s` ≤ sender
  on-connection read `45s`. The on-connection read window is **independent of
  `--wait`** (which only bounds the later inbox poll).
- **Flag interactions.** `--reply-on-conn` rejects `--type binary` (the request
  is sent as a text query); it is ignored under `--trace` (trace wins); and it
  forces a fresh connection per send (an `--auto-answer` receiver closes after
  one request+reply, so `--reuse-conn` cannot apply).

## Limitations

- **Scope: receivers that run a client which reads the reply.** Reply-on-connection
  delivers to any sender whose client reads the reply off the connection (updated
  `pilotctl`/SDK). It does not change outcomes for transient clients that have no
  daemon/inbox at all.
- **Sender-side fan-out is out of scope.** A single requester daemon opening
  *many* simultaneous dials (dozens at once) can hit sender-side `dial` failures
  under NAT/relay pressure. This is a property of overloading one sender daemon —
  not of the `--auto-answer` receiver, which dropped zero replies under test.
  Regular requesters issue only a few dials and are unaffected; we do not expect
  or support a single requester fanning out at that level.
