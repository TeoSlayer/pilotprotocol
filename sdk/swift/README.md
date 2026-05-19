# Pilot — Swift SDK

End-to-end-encrypted peer-to-peer messaging for iOS and macOS apps,
built on the [Pilot Protocol](https://pilotprotocol.network/) overlay
network.

The SDK ships the `pilot-daemon` Go core compiled to a static
library inside an `XCFramework`. Your app links against it, calls a
Swift API, and gets a real Pilot node — no separate process, no
external daemon, no system-wide socket. Single-process, sandbox-clean.

## What this gives you

- Ed25519 identity (generated on first launch, persisted at `dataDir`)
- Registration with the Pilot registry
- Mutual-trust handshake with arbitrary nodes
- Encrypted UDP tunnels (X25519 + AES-256-GCM), NAT-traversed via beacons
- Application-level send/receive (`SendTo` / `RecvFrom`)
- All the same protocol the macOS/Linux `pilot-daemon` speaks

## What this does *not* give you yet

- iOS background-suspended operation. The embedded daemon runs in
  your app's process; when iOS suspends the app, the daemon pauses.
  Use `BGAppRefreshTask` or push-triggered wake for catch-up; for
  always-on, you need a `NEPacketTunnelProvider` extension (out of
  scope for v0).
- Identity stored in Secure Enclave. v0 writes `identity.json` to
  the sandbox as plaintext. Sealing the Ed25519 key behind an SE-
  backed wrapping key is on the roadmap.

## Quick start

```swift
import Pilot

// Pick a writable directory inside your app sandbox. ApplicationSupport
// is the usual choice. The socket path must be SHORT (Unix sun_path
// is 104 bytes); pass a basename and Pilot will chdir into dataDir.
let dataDir = FileManager.default
    .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("pilot")

let pilot = try Pilot.start(.init(
    dataDir: dataDir,
    socketPath: "p.sock",
    trustAutoApprove: true,
    keepaliveSeconds: 30
))

print("address=\(pilot.start.address) node_id=\(pilot.start.nodeID)")

// Send to a known peer
try pilot.handshake(peerID: 12345, justification: "hello")
_ = try pilot.waitForTrust(peerID: 12345, timeoutMs: 30_000)
try pilot.send(to: "0:0000.0000.AAAA", port: 7777, data: Data("hi".utf8))

// Receive in a background task
Task {
    while let dg = try? pilot.receive() {
        print("got \(dg.data.count) bytes from \(dg.srcAddr):\(dg.srcPort)")
    }
}

// On shutdown
try pilot.stop()
```

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│ Your iOS app (Swift)                                       │
│   ┌──────────────────────────────────────────────────────┐ │
│   │ Pilot.swift  — typed Swift API, async-ready          │ │
│   └────────────────────┬─────────────────────────────────┘ │
│                        │ C ABI (47 functions)              │
│   ┌────────────────────▼─────────────────────────────────┐ │
│   │ libPilot.a (cgo static library, ~12 MB)              │ │
│   │   • PilotEmbeddedStart/Stop  — daemon lifecycle      │ │
│   │   • PilotConnect/Info/Health — driver client         │ │
│   │   • PilotHandshake/WaitForTrust/SendTo/RecvFrom      │ │
│   ├──────────────────────────────────────────────────────┤ │
│   │ pkg/daemon  — full Pilot daemon, in-process          │ │
│   │   • Ed25519 identity                                 │ │
│   │   • Registry RPC (length-prefixed JSON over TCP)     │ │
│   │   • Beacon NAT-traversal                             │ │
│   │   • Noise-style tunnel (X25519 + AES-256-GCM)        │ │
│   │   • Handshake state machine + trust persistence      │ │
│   │   • Unix socket IPC (inside the sandbox)             │ │
│   └──────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────┘
                              ↓ network
        ┌─────────────────────┴─────────────────────┐
        │ Pilot registry (34.71.57.205:9000)         │
        │ Pilot beacon   (34.71.57.205:9001)         │
        └────────────────────────────────────────────┘
```

## Building from source

The xcframework is regenerated from `sdk/cgo` by the build script.

```sh
sdk/swift/scripts/build-xcframework.sh
```

Produces `sdk/swift/Frameworks/Pilot.xcframework` with three slices:

- `ios-arm64` — iOS device (iPhone/iPad)
- `ios-arm64-simulator` — iOS simulator on Apple Silicon
- `macos-arm64` — macOS arm64 (for `swift test` and host dev)

The script invokes `go build -buildmode=c-archive` with cross-
compilation flags for each target SDK, generates header + module
map per slice, and bundles via `xcodebuild -create-xcframework`.

## Smoke testing

```sh
# Boot a simulator if you haven't.
xcrun simctl boot "iPhone 17"

# Run the Swift smoke in the simulator. Three modes:
sdk/swift/scripts/run-smoke-sim.sh info
sdk/swift/scripts/run-smoke-sim.sh alice
sdk/swift/scripts/run-smoke-sim.sh bob <peer_id> <peer_addr>
```

For a full peer-to-peer test (alice on host Go, bob in sim Swift),
see the orchestration recipe in `Examples/pilot-smoke-swift/`.

## Known constraints

- **One Pilot per process.** The embedded daemon is process-global.
  Create a single `Pilot` at app launch and reuse it.
- **Socket path ≤ 100 bytes.** Unix `sun_path` is 104 bytes on
  darwin/ios. iOS Application Support paths already approach the
  limit. Pass a relative basename; `Pilot.start` will `chdir(dataDir)`
  so it lands inside your sandbox.
- **Stranded test nodes.** Every `Pilot.start` registers a fresh
  identity with the registry. There's no GC of unused nodes today;
  if you generate many test identities, drop the registered nodes
  via `pilotctl deregister` after the run.
- **No `NetworkExtension` entitlement needed** for outbound traffic.
  iOS apps can open arbitrary outbound TCP/UDP sockets to the public
  internet without special permission.

## License

AGPL-3.0-or-later. See `LICENSE` at the repo root.
