# Cloudflare Workers Compatibility — Feasibility Brief

**Branch:** `investigate/cloudflare-workers-compat`
**Date:** 2026-05-12
**Question:** Can the Pilot Protocol SDK run inside a Cloudflare Worker with `nodejs_compat`?

## TL;DR

**The current Node SDK cannot run on Workers, period.** Two non-negotiable blockers:

1. **The SDK loads `libpilot.dylib/so/dll` via `koffi` (FFI).** Workers do not support native FFI / N-API. There is no path to load a Go-compiled shared library.
2. **The pilot protocol uses UDP.** Workers' `node:dgram` is documented as *"partially supported (non-functional)"* — present as an importable stub, but does nothing. There is no raw UDP transport available in the Workers runtime.

A new "Workers-compatible" mode is buildable, but it is a new architecture, not a port of the existing SDK. See `Architecture options` below.

## Constraint matrix (verified 2026-05-12)

| Workers / `nodejs_compat` capability | Pilot needs it for | Status |
|---|---|---|
| `node:dgram` (UDP) | the entire wire protocol | ❌ non-functional stub |
| `node:net` (raw TCP) | could replace UDP via a tunnel | ✅ supported |
| `node:fs` | identity.json, trust.json, config | ✅ supported (ephemeral; pair with KV/D1/R2 for persistence) |
| Native FFI / N-API | `koffi` → `libpilot.so` | ❌ not supported |
| `child_process` | spawning the daemon | ❌ non-functional stub |
| WebSocket client | tunnelled relay | ✅ supported via fetch upgrade |
| `crypto` (Web Crypto + node:crypto subset) | X25519, Ed25519, AES-256-GCM | ✅ supported — but X25519 is via SubtleCrypto only |
| Outbound `connect()` TCP | tunnel transport | ✅ supported (port 25 blocked, Cloudflare IPs blocked, no localhost / private IPs) |

Source: <https://developers.cloudflare.com/workers/runtime-apis/nodejs/>, <https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/>.

## Where the current SDK stops being portable

The Node SDK is structured as:

```
sdk/node/src/
  ├── ffi.ts      ← koffi loads libpilot.{so,dylib,dll}
  ├── client.ts   ← Driver wrapper, marshals JSON over FFI
  ├── runtime.ts  ← library discovery + lifecycle
  └── cli.ts      ← pilotctl shim
```

`libpilot` is built from `sdk/cgo/bindings.go` — it embeds the full Go daemon's *driver* (the unix-socket client side that talks to a running `pilot-daemon` over the IPC socket).

In a Worker, every link of that chain fails:
- `koffi.load('libpilot.dylib')` → no FFI runtime
- Even if the library loaded, it would `unix.Dial('/tmp/pilot.sock')` → no Unix sockets and no daemon process
- Even if the daemon ran, it binds a UDP socket → no UDP

So the SDK is not *partially* incompatible — it is foundationally incompatible.

## Architecture options for Pilot-on-Workers

### Option A — HTTP/WebSocket bridge daemon ("Pilot Gateway")

Run a regular daemon on conventional infra (VM, k8s pod, Fly.io, etc.) with full UDP access. Expose a TCP-reachable bridge: HTTP for request/reply operations (`/data`, info, lookup) + WebSocket for streaming (recvFrom, events, tunneled conns).

```
┌────────────────┐    HTTPS/WSS     ┌──────────────────┐    UDP    ┌────────┐
│ Cloudflare     │ ───────────────► │ pilot-bridge     │ ────────► │ peer   │
│ Worker         │ ◄─────────────── │  daemon (+ HTTP) │ ◄──────── │ daemon │
└────────────────┘                  └──────────────────┘           └────────┘
```

**Pros:**
- Worker becomes a thin client; nothing about its identity is special-cased on the wire (it inherits the bridge's identity, or has its own which the bridge proxies for).
- We can ship in days, not months — the bridge is just an HTTP wrapper around `driver.Driver`.
- TLS termination at the bridge; auth via a per-Worker bearer token.

**Cons:**
- The Worker isn't really a Pilot peer — it's *piggybacking on* a daemon. From the network's perspective, it's the bridge that has identity/trust.
- Extra hop = extra latency (50–200 ms depending on geographic placement).
- Bridge becomes a fan-in chokepoint — needs to scale horizontally with multiple bridges per region.

**Effort estimate:** ~1–2 weeks. New `cmd/pilot-bridge/` binary, `sdk/workers/` package, auth model, deployment story.

### Option B — Pure-JS Pilot client over WebSocket-tunneled UDP

Build a pure-TypeScript implementation of the Pilot wire protocol (handshake/PILA, AEAD envelope, replay window, KE state). The Worker becomes a real Pilot peer with its own identity. UDP packets are tunneled over a WebSocket connection to a "WS-UDP relay" service.

```
┌────────────────┐    WSS (UDP-in-frames)    ┌──────────────────┐    UDP    ┌────────┐
│ Cloudflare     │ ─────────────────────────►│ ws-udp-relay     │ ────────► │ peer   │
│ Worker         │ ◄─────────────────────────│  (stateless)     │ ◄──────── │ daemon │
│  (Pilot peer)  │                           └──────────────────┘           └────────┘
└────────────────┘
```

**Pros:**
- Worker is a *real peer* with its own keys, address, and trust state.
- Relay is stateless and trivially horizontally scalable.
- Long-term answer: the relay can later be replaced by direct UDP if Workers ever gains it.

**Cons:**
- Substantial new TS implementation — the Go protocol code is ~10k LOC, the subset we'd port is ~2–3k LOC (envelope + handshake + replay-window + key-exchange + ECDH/AEAD via WebCrypto).
- Have to keep the TS implementation in sync with future Go changes (the existing FFI approach has the Go code as single source of truth).
- WebSocket → UDP mapping has its own edge cases (frame ordering, MTU, reconnects, NAT-keepalive equivalent).
- Worker CPU budget (typical 50–100 ms per request, or up to 5 min on "unbound") needs careful pacing for handshakes + retransmits.

**Effort estimate:** ~6–10 weeks. New `sdk/workers-ts/` with pure-TS protocol, new `cmd/ws-udp-relay/` for the tunneling endpoint, conformance test suite to keep parity with Go.

### Option C — Pilot REST API ("agentless" mode)

The most pragmatic. Expose a REST API on a managed Pilot endpoint (think: `pilot.cloud/v1/send` etc.). Workers hit the API like any other HTTP service. Auth via API key.

**Pros:**
- Workers don't need to know Pilot exists. Any client of `fetch()` works.
- Stateless from the Worker's side.

**Cons:**
- The user loses the "agent is a network citizen" property — every Worker call is just an HTTP request to a centralized endpoint.
- Conceptually closer to "API gateway" than "Pilot peer" — semantically different product.

**Effort estimate:** ~3–5 days. The bridge from Option A is most of the work; the API surface is small.

### Option D — Go-to-WASM hybrid: pure logic in Go-compiled-WASM, transport in TS

The middle path. Compile the pilot protocol's **pure logic** (crypto, replay window, envelope packing/unpacking, key-exchange state machine, replay-recovery gates) to WebAssembly. Keep the **transport** (UDP→WS, fetch, TLS) in TypeScript using Workers' `connect()`. The WASM module exports a small surface like:

```
// In the WASM module (Go):
pilot_handshake_build(...) → bytes
pilot_handshake_handle(state, bytes) → bytes
pilot_envelope_encrypt(state, plain) → bytes
pilot_envelope_decrypt(state, encrypted) → plain | error_code
```

The TypeScript side owns sockets, timers, retx loops, and feeds bytes into the WASM.

**Feasibility check (verified 2026-05-12):**

| Constraint | Limit | Pilot fit |
|---|---|---|
| Worker bundle, gzipped | 3 MB free / 10 MB paid | A standard Go WASM is ~10 MB raw, ~3 MB gzipped — **right at the free-tier ceiling, fits paid** |
| Worker bundle, uncompressed | 64 MB | trivially fits |
| WASI support | "experimental, only some syscalls" | irrelevant — we'd use the host-import bridge, not WASI |
| Go→WASM target | `GOOS=js GOARCH=wasm` (browser-shim) or `GOOS=wasip1 GOARCH=wasm` | use `wasm_exec.js`-style shim with custom host imports |
| TinyGo size | ~200–500 KB for our subset | better fit, *but* TinyGo's incomplete support for goroutines / channels / reflect would force us to refactor away those constructs in the pilot packages we compile |

**What CAN be compiled to WASM:**
- `internal/crypto` (Ed25519 sign/verify, X25519 derive)
- `pkg/daemon/envelope` (AEAD wrap/unwrap, replay window check, ReplayCount + ShouldDropOnReplay)
- `pkg/daemon/keyexchange/crypto.go` (key material structs, Salvage, threshold gates)
- `pkg/daemon/keyexchange/handle.go` (PILA build / parse — pure function over bytes)
- `pkg/protocol/*` (frame encode/decode, addr parse, checksum)

**What CANNOT be compiled (or only with refactoring):**
- `pkg/daemon/tunnel.go` (uses `net.UDPConn`, time.Ticker loops, goroutines for routing — needs to live in TS)
- `pkg/daemon/routing` (similar)
- `pkg/daemon/udpio` (literal UDP)
- Anything using `os.File` or external processes
- The retransmit loop (a TS `setTimeout`/`Promise` loop calling into the WASM each tick)

**Pros:**
- Go source remains single source of truth for protocol *correctness* (handshake bytes, AEAD framing, replay-window bit math).
- The fiddly bits — exact byte layouts, AAD construction, nonce composition — are tested by the existing Go test suite and ship via WASM, not retyped in TS.
- Vastly smaller TS surface than Option B (just the I/O loops + driver-style API).
- Future Go-side protocol changes auto-flow into WASM with `make wasm` rebuild.

**Cons:**
- Two languages for one library — debugging spans both.
- Goroutine→TS event-loop bridging is non-trivial. The WASM module must be designed so all its "callbacks" surface as deterministic return values rather than spawning goroutines.
- Standard Go's WASM runtime is ~3 MB gzipped — right at the free-tier ceiling. TinyGo would solve that but cuts off goroutines, which the asymmetric-recovery code relies on (background retx). We'd need to refactor those into "step functions" the TS driver calls each tick.
- Need a custom `wasm_exec.js` shim that imports Workers' `connect()` / `crypto.subtle` / `setTimeout` into the wasm host. Cloudflare's WASI is experimental and lacks sockets, so we can't lean on it.

**Effort estimate:** ~4–6 weeks. Faster than Option B (no protocol re-implementation), slower than Option A (still need the wasm host shim + a redesigned step-function-friendly protocol surface in the Go code).

### Option D variant — separate the WASM module from the Worker

Cloudflare Workers can `import` WASM modules as binary assets. The wasm module can be a `.wasm` file *not* counted in the Worker bundle if loaded via service binding or Workers AI / R2. This unblocks the size limit but adds a fetch-on-cold-start hit.

## Recommendation

If the goal is **"agents on Workers can talk to Pilot peers"**, ship **Option A first** (HTTP/WebSocket bridge) as a 1–2-week deliverable. The Worker stays a thin client; the bridge holds the keys; the rest of the Pilot fleet sees a normal peer.

If the goal is **"Cloudflare Workers become first-class Pilot peers with their own identity"** (the more interesting product), **Option D (Go→WASM hybrid)** is the right long-term answer — single source of truth for protocol correctness stays in Go, but the Worker really is a peer. Plan ~4–6 weeks. If TinyGo's stdlib constraints prove too painful for the recovery loops (goroutines), fall back to **Option B** (pure-TS port) for ~6–10 weeks at the cost of maintaining a second protocol implementation.

Option C is only attractive if the audience is "developers who want Pilot data but don't care about being agents" — which is a different product.

## Next concrete steps for Option A (if chosen)

1. Sketch the bridge wire format — likely JSON-RPC 2.0 over HTTPS for unary calls + WebSocket for bidi streams (recv, events).
2. Auth: per-bridge-tenant API key; bridge has one Pilot identity, proxies all tenants' calls under that identity.
3. Write `sdk/workers/` — a TS module that targets the Workers `connect()` / `fetch()` API surface, no `node:fs` / `node:dgram` / `koffi` references.
4. Conformance smoke: a Worker on a real `*.workers.dev` that does `bridge.info()` and `bridge.sendMessage('list-agents', '/data {}')` against a real bridge deployment.

## Outstanding questions

- **Identity model**: does each Worker tenant get its own Pilot node_id (bridge proxies trust handshakes per tenant), or share the bridge's? Affects ~everything downstream.
- **Egress cost**: high-traffic Workers calling the bridge would generate non-trivial egress between the bridge VM and Cloudflare's network. Likely acceptable; worth modelling.
- **WebCrypto X25519 availability**: confirmed supported per the Cloudflare docs, but worth a `crypto.subtle.deriveKey(...{name:'X25519'})` spike before committing to Option B.
