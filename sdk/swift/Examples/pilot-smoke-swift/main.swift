// SPDX-License-Identifier: AGPL-3.0-or-later
//
// pilot-smoke-swift — Swift counterpart of cmd/embedded-smoke.
//
// Modes:
//   info               — boot, fetch Info/Health, shut down.
//   alice              — boot with auto-approve, print
//                        ALICE_READY node_id=N addr=A, block on
//                        receive(), exit on first datagram.
//   bob PEER_ID ADDR   — boot, handshake the peer, waitForTrust,
//                        send "hi from bob", exit.

import Foundation
// In the Swift Package this would be `import Pilot`. For the
// freestanding swiftc compile we include Pilot.swift directly
// alongside this file, so the symbols are already in scope.

@discardableResult
func main() -> Int32 {
    let args = CommandLine.arguments
    let mode = args.count >= 2 ? args[1] : "info"

    let dataDir = URL(
        fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("pilot-swift-\(UUID().uuidString.prefix(8))")

    let cfg = Pilot.Config(
        dataDir: dataDir,
        socketPath: "p.sock",
        trustAutoApprove: (mode != "info"),
        keepaliveSeconds: 2
    )

    let pilot: Pilot
    do {
        pilot = try Pilot.start(cfg)
    } catch {
        FileHandle.standardError.write(Data("FAIL: start: \(error)\n".utf8))
        return 1
    }
    defer { try? pilot.stop() }

    do {
        switch mode {
        case "info":
            return try runInfo(pilot)
        case "alice":
            return try runAlice(pilot)
        case "bob":
            guard args.count >= 4,
                  let peerID = UInt32(args[2])
            else {
                FileHandle.standardError.write(Data(
                    "usage: pilot-smoke-swift bob PEER_ID PEER_ADDR\n".utf8))
                return 2
            }
            return try runBob(pilot, peerID: peerID, peerAddr: args[3])
        default:
            FileHandle.standardError.write(Data(
                "unknown mode \(mode); want info|alice|bob\n".utf8))
            return 2
        }
    } catch {
        FileHandle.standardError.write(Data("FAIL: \(error)\n".utf8))
        return 1
    }
}

func runInfo(_ p: Pilot) throws -> Int32 {
    print("node_id=\(p.start.nodeID) addr=\(p.start.address)")
    let info = try p.info()
    print("--- Info ---\n\(info)")
    let health = try p.health()
    print("--- Health ---\n\(health)")
    print("SMOKE OK")
    return 0
}

func runAlice(_ p: Pilot) throws -> Int32 {
    print("ALICE_READY node_id=\(p.start.nodeID) addr=\(p.start.address)")
    FileHandle.standardOutput.synchronizeFile()

    // Block on first datagram. Pilot.receive() is synchronous; iOS
    // would wrap this in a Task and an AsyncStream.
    let dg = try p.receive()
    let body = String(data: dg.data, encoding: .utf8) ?? "<binary>"
    print("ALICE_RECV src=\(dg.srcAddr) src_port=\(dg.srcPort) dst_port=\(dg.dstPort) data=\"\(body)\"")

    let peers = try p.trustedPeers()
    print("--- TrustedPeers --- \(peers)")
    print("SMOKE OK")
    return 0
}

func runBob(_ p: Pilot, peerID: UInt32, peerAddr: String) throws -> Int32 {
    print("BOB_START node_id=\(p.start.nodeID) addr=\(p.start.address) peer_id=\(peerID) peer_addr=\(peerAddr)")
    try p.handshake(peerID: peerID, justification: "pilot-swift-smoke")
    let trusted = try p.waitForTrust(peerID: peerID, timeoutMs: 90_000)
    print("BOB_TRUST trusted=\(trusted)")
    guard trusted else {
        FileHandle.standardError.write(Data("FAIL: trust not established\n".utf8))
        return 1
    }
    let payload = Data("hi from bob (swift, node_id=\(p.start.nodeID), addr=\(p.start.address))".utf8)
    try p.send(to: peerAddr, port: 7777, data: payload)
    print("BOB_SENT to=\(peerAddr) port=7777 bytes=\(payload.count)")
    // Let the tunnel flush before tearing down.
    Thread.sleep(forTimeInterval: 2.0)
    print("SMOKE OK")
    return 0
}

exit(main())
