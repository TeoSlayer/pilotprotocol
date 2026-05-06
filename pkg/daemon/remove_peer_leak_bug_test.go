// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"
)

// TestRemovePeerLeavesPerPeerMetadataMapsStale reproduces the
// "RemovePeer leaks per-peer metadata" bug.
//
// Symptom: TunnelManager has eight per-peer maps that get populated
// during the lifetime of a peer relationship:
//  1. peers              — populated on AddPeer/handleEncrypted/key-exchange
//  2. crypto             — populated on key-exchange paths
//  3. lastOutboundSend   — populated on every writeFrame success (iter 7)
//  4. sendErrCount       — populated on ICMP-unreachable errors (iter 8)
//  5. lastDirectRecv     — populated on every authenticated decrypt (iter 5/3)
//  6. blackholeMissCount — populated by writeFrame's hysteresis (iter 3)
//  7. directClearCount   — populated by clearRelayOnDirectLocked (iter 3)
//  8. relayPeers         — populated by relay flip / SetRelayPeer / iter 8
//  9. peerPubKeys        — populated on auth key-exchange
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
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0x12345678
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4000}

	// Pre-populate every per-peer map under tm.mu.
	tm.mu.Lock()
	tm.peers[peerNodeID] = addr
	tm.lastOutboundSend[peerNodeID] = time.Now()
	tm.sendErrCount[peerNodeID] = 2
	tm.lastDirectRecv[peerNodeID] = time.Now()
	tm.blackholeMissCount[peerNodeID] = 1
	tm.directClearCount[peerNodeID] = 1
	tm.relayPeers[peerNodeID] = true
	tm.peerPubKeys[peerNodeID] = make([]byte, 32) // dummy Ed25519 pubkey
	tm.mu.Unlock()

	// pendingRekey + lastInboundDecrypt under rkPendingMu.
	tm.rkPendingMu.Lock()
	tm.pendingRekey[peerNodeID] = &pendingRekeyState{lastSentAt: time.Now()}
	tm.lastInboundDecrypt[peerNodeID] = time.Now()
	tm.rkPendingMu.Unlock()

	tm.RemovePeer(peerNodeID)

	// FIXED: every per-peer map entry is cleared.
	tm.mu.RLock()
	leaked := []string{}
	if _, ok := tm.peers[peerNodeID]; ok {
		leaked = append(leaked, "peers")
	}
	if _, ok := tm.lastOutboundSend[peerNodeID]; ok {
		leaked = append(leaked, "lastOutboundSend")
	}
	if _, ok := tm.sendErrCount[peerNodeID]; ok {
		leaked = append(leaked, "sendErrCount")
	}
	if _, ok := tm.lastDirectRecv[peerNodeID]; ok {
		leaked = append(leaked, "lastDirectRecv")
	}
	if _, ok := tm.blackholeMissCount[peerNodeID]; ok {
		leaked = append(leaked, "blackholeMissCount")
	}
	if _, ok := tm.directClearCount[peerNodeID]; ok {
		leaked = append(leaked, "directClearCount")
	}
	if _, ok := tm.relayPeers[peerNodeID]; ok {
		leaked = append(leaked, "relayPeers")
	}
	if _, ok := tm.peerPubKeys[peerNodeID]; ok {
		leaked = append(leaked, "peerPubKeys")
	}
	tm.mu.RUnlock()

	tm.rkPendingMu.Lock()
	if _, ok := tm.pendingRekey[peerNodeID]; ok {
		leaked = append(leaked, "pendingRekey")
	}
	if _, ok := tm.lastInboundDecrypt[peerNodeID]; ok {
		leaked = append(leaked, "lastInboundDecrypt")
	}
	tm.rkPendingMu.Unlock()

	if len(leaked) > 0 {
		t.Errorf("RemovePeer left %d per-peer map(s) populated: %v", len(leaked), leaked)
	}
}
