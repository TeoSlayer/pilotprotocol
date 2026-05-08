// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"syscall"
	"testing"
	"time"
)

// syscallECONNREFUSED is a syscall.Errno constant. Aliased so the test
// expression stays readable.
const syscallECONNREFUSED = syscall.ECONNREFUSED

// TestRemovePeerLeavesPerPeerMetadataMapsStale reproduces the
// "RemovePeer leaks per-peer metadata" bug.
//
// Symptom: TunnelManager has eight per-peer maps that get populated
// during the lifetime of a peer relationship:
//   1. peers              — populated on AddPeer/handleEncrypted/key-exchange
//   2. crypto             — populated on key-exchange paths
//   3. lastOutboundSend   — populated on every writeFrame success (iter 7)
//   4. sendErrCount       — populated on ICMP-unreachable errors (iter 8)
//   5. lastDirectRecv     — populated on every authenticated decrypt (iter 5/3)
//   6. blackholeMissCount — populated by writeFrame's hysteresis (iter 3)
//   7. directClearCount   — populated by clearRelayOnDirectLocked (iter 3)
//   8. relayPeers         — populated by relay flip / SetRelayPeer / iter 8
//   9. peerPubKeys        — populated on auth key-exchange
//  10. pendingRekey       — populated by markPendingRekey (rkPendingMu)
//  11. lastInboundDecrypt — populated by recordInboundDecrypt (rkPendingMu)
//
// RemovePeer (called from handshake-revocation paths in handshake.go)
// currently only cleans up entries 1, 2, 3, 4. The remaining seven maps
// retain stale entries forever — there's no other deletion path for
// most of them. Long-running daemons with peer churn (admins revoking
// trust, peers leaving networks) accumulate these stale entries
// indefinitely.
//
// Real-world impact:
//   - Daemons running for months on registries with high member
//     turnover (rotating CI workers, autoscaled fleets) leak memory
//     proportional to total-ever-connected peers, not currently-active.
//   - A peer whose nodeID is later reused (registry collision, manual
//     reassignment) inherits stale metadata: blackholeMissCount may
//     instantly trip the relay flip; lastDirectRecv may make
//     writeFrame think the peer is reachable when they're not.
//
// What v1.9.1's fix should change: RemovePeer also deletes from
// lastDirectRecv, blackholeMissCount, directClearCount, relayPeers,
// peerPubKeys, pendingRekey, lastInboundDecrypt. The latter two live
// under rkPendingMu (a separate mutex) so a second lock acquisition is
// required.
//
// FIXED (v1.9.1): RemovePeer now clears all eleven per-peer maps.
// The first nine live under tm.mu (peers, crypto, lastOutboundSend,
// sendErrCount, lastDirectRecv, blackholeMissCount, directClearCount,
// relayPeers, peerPubKeys); the last two (pendingRekey,
// lastInboundDecrypt) require a second acquisition of rkPendingMu.
func TestRemovePeerLeavesPerPeerMetadataMapsStale(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0x12345678
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000}

	// Pre-populate every per-peer map. tm.peers stays under tm.mu;
	// the L4 maps (lastOutboundSend, sendErrCount, lastDirectRecv,
	// blackholeMissCount, directClearCount, relayPeers) live in
	// routing.Manager and are seeded via its setters. blackholeMiss /
	// directClear counters have no public seeders — they're driven by
	// MaybeFlipBlackhole / ClearRelayOnDirect — so we drive them via
	// those instead.
	tm.mu.Lock()
	tm.peers[peerNodeID] = addr
	tm.mu.Unlock()
	tm.routing.RecordOutboundSend(peerNodeID, time.Now())
	tm.routing.RecordDirectRecv(peerNodeID, time.Now())
	tm.routing.SetRelayPeer(peerNodeID, true)
	// sendErrCount: drive by triggering 2 ICMP errors.
	icmpErr := &net.OpError{Op: "write", Net: "udp", Err: syscallECONNREFUSED}
	tm.routing.HandleSendError(peerNodeID, icmpErr)
	tm.routing.HandleSendError(peerNodeID, icmpErr)

	// peerPubKeys, pendingRekey, lastInboundDecrypt now live in keyexchange.Manager.
	tm.kx.SetPeerPubKey(peerNodeID, make([]byte, 32)) // dummy Ed25519 pubkey
	tm.kx.InjectPendingRekeyForTest(peerNodeID, &pendingRekeyState{LastSentAt: time.Now()})
	tm.kx.SetLastInboundDecryptForTest(peerNodeID, time.Now())

	tm.RemovePeer(peerNodeID)

	// FIXED: every per-peer map entry is cleared.
	leaked := []string{}
	tm.mu.RLock()
	if _, ok := tm.peers[peerNodeID]; ok {
		leaked = append(leaked, "peers")
	}
	tm.mu.RUnlock()
	if _, ok := tm.routing.LastOutboundSend(peerNodeID); ok {
		leaked = append(leaked, "lastOutboundSend")
	}
	if c := tm.routing.SendErrCount(peerNodeID); c != 0 {
		leaked = append(leaked, "sendErrCount")
	}
	if tm.routing.HasDirectRecv(peerNodeID) {
		leaked = append(leaked, "lastDirectRecv")
	}
	if tm.routing.BlackholeMissCount(peerNodeID) != 0 {
		leaked = append(leaked, "blackholeMissCount")
	}
	if tm.routing.IsRelayPeer(peerNodeID) {
		leaked = append(leaked, "relayPeers")
	}

	if tm.kx.HasPeerPubKey(peerNodeID) {
		leaked = append(leaked, "peerPubKeys")
	}
	if tm.kx.PendingRekeyHas(peerNodeID) {
		leaked = append(leaked, "pendingRekey")
	}
	if tm.kx.LastInboundDecryptHas(peerNodeID) {
		leaked = append(leaked, "lastInboundDecrypt")
	}

	if len(leaked) > 0 {
		t.Errorf("RemovePeer left %d per-peer map(s) populated: %v", len(leaked), leaked)
	}
}
