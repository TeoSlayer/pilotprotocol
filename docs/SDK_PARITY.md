# SDK API parity

Audit of the public API surface across `sdk-node`, `sdk-python`, and
`sdk-swift`. Tracks PILOT-42.

**Canonical matrix:** [Google Sheet — PILOT-42 SDK Parity Matrix][sheet]
(upload `scripts/parity-audit/inventory/matrix.csv` to refresh).

[sheet]: https://docs.google.com/spreadsheets/d/TODO-SHEET-ID/edit "Pending Sheet creation — see PILOT-42"

**Audit run:** 2026-05-28 against
`sdk-node@d02bd00`, `sdk-python@93584ea`, `sdk-swift@0d49f87`.

## How to re-run

```bash
python3 scripts/parity-audit/build_matrix.py \
    --node-root   ../sdk-node   \
    --python-root ../sdk-python \
    --swift-root  ../sdk-swift  \
    --out-dir     ./inventory
```

See `scripts/parity-audit/README.md` for what each output file contains and
how `gap_type` is assigned.

## Snapshot: where each SDK stands

The full method-level matrix lives in the Google Sheet linked above. This
table summarizes parity by category — useful for offline review.

| Category | Methods | sdk-node | sdk-python | sdk-swift | Status |
|---|---|---|---|---|---|
| Lifecycle (construct / dispose) | 2 | ✅ | ✅ | ✅ | full parity (idiomatic per language) |
| Daemon admin (`info` / `health`) | 2 | ✅ | ✅ | ✅ | full parity |
| Daemon admin (`rotateKey`) | 1 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Trust handshake — initiate, list | 2 | ✅ | ✅ | ✅ | full parity |
| Trust admin (`approve` / `reject` / `pending` / `revoke`) | 4 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Trust convenience (`waitForTrust`) | 1 | ❌ | ❌ | ✅ | unintentional gap in node + python |
| Datagrams (`sendTo` / `recvFrom`) | 2 | ✅ | ✅ | ✅ | full parity (different signature shape) |
| Datagrams (`broadcast`) | 1 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Streams (`dial` / `listen` / `disconnect`) | 3 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| `Conn` type + methods (`read` / `write` / `setReadDeadline` / `close`) | 5 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| `Listener` type + methods (`accept` / `close`) | 3 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Registry admin (hostname / visibility / deregister / tags / webhook) | 6 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Networks (list/join/leave/members/invite/pollInvites/respondInvite) | 7 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Managed networks (score/status/rankings/forceCycle/reconcile) | 5 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Policy (get/set) | 2 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| Member tags (get/set) | 2 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| High-level services (`sendMessage` / `sendFile` / `publishEvent` / `subscribeEvent`) | 4 | ✅ | ✅ | ❌ | unintentional gap in Swift |
| FFI loader (`findLibrary` / `loadLibrary`) | 2 | ✅ | (private) | n/a | intentional — Swift uses XCFramework, no loader needed |
| `DEFAULT_SOCKET_PATH` constant | 1 | ✅ | ✅ | n/a | intentional — Swift's embedded daemon has per-instance sockets |
| Typed response structs (`Config` / `StartResult` / `Datagram` / `Error`) | 4 | n/a | n/a | ✅ | convention — Swift idiom; node/python return untyped dicts |

## Totals

- **80** canonical rows in the matrix (after merging language-idiomatic equivalents)
- **10** rows at full parity
- **21** rows classified as `convention` (language idioms, not real gaps)
- **3** rows classified as `intentional` gaps (justified by platform)
- **46** rows classified as `unintentional` gaps — **the work backlog**

Of the 46 unintentional gaps:

- **45 in sdk-swift** — covering streams, networks, managed networks, policy,
  member tags, high-level services, registry admin, and most trust admin.
  Tracked as **[PILOT-200](https://vulturelabs.atlassian.net/browse/PILOT-200)**.
- **1 in sdk-node + sdk-python** — `waitForTrust(peerID, timeoutMs) → bool`,
  the blocking convenience Swift already has. Tracked as
  **[PILOT-201](https://vulturelabs.atlassian.net/browse/PILOT-201)** (node)
  and **[PILOT-202](https://vulturelabs.atlassian.net/browse/PILOT-202)** (python).

## What counts as a gap

The matrix collapses idiomatic equivalents so naming differences across
languages don't inflate the gap count:

- Constructors: `Driver()` (Node/Python) ≡ `Pilot.start(config)` (Swift) — same operation, different shape.
- Cleanup: `Driver.close()` (Node/Python) ≡ `Pilot.stop()` (Swift) ≡ `Driver.__exit__` (Python's `with`) ≡ `Driver[Symbol.dispose]` (Node's `using`) — same operation.
- Datagram send: `sendTo(addr, data)` (Node/Python) ≡ `send(to: peerAddr, port:, data:)` (Swift) — same operation, different signature shape.
- Datagram receive: `recvFrom() → dict` (Node/Python) ≡ `receive() → Datagram` (Swift) — same operation; Swift returns a typed struct.
- snake_case ↔ camelCase: each Python `snake_case` method maps to the same canonical name as its Node/Swift `camelCase` equivalent.

These are **not** counted as gaps. Real gaps are *operations* not exposed at
all by an SDK — see the `unintentional` rows in `matrix.csv`.

## End-state target

Full parity except the 3 intentional rows above. The Swift typed-response
structs may stay Swift-only (they're idiomatic Swift), but node/python should
consider adding TypedDict/interface-typed return overloads in a future
release to close the typing-convention gap too.

## Future re-audits

Run `build_matrix.py` after every minor release across the three SDKs.
The script outputs are deterministic against a given commit triple, so a
subsequent re-run with the same SHAs produces byte-identical CSV — making
this safe to wire into CI as a regression gate if we ever want to enforce
"no new gaps without classification."
