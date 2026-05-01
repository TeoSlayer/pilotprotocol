// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

// TestICMPUnreachableIgnoredByWriteFrame reproduces the "dead peer
// stays warm" bug.
//
// Symptom: a peer's daemon process dies (port closed, host unreachable,
// network removed). Their kernel sends ICMP unreachable in response to
// our UDP packets. The Linux kernel queues this on our socket; the next
// WriteToUDP returns ECONNREFUSED (or EHOSTUNREACH / ENETUNREACH for
// host-level outages). We currently propagate the error from
// writeFrame to the caller and DO NOTHING semantic — the peer stays in
// tm.peers, the keepalive loop (iter 7) keeps emitting pings to them,
// the blackhole heuristic (iter 3) takes 24+ s to flip them to relay,
// and any in-flight Connection's retransmit timer wastes its budget on
// a dead path.
//
// Real-world impact: peer crashes during a transfer, our daemon spends
// the next ~24 s pretending the peer is still up. Connection retries
// burn through their max attempts before the relay flip happens.
//
// What v1.9.1's ICMP-error-aware fix should change:
//   - Track per-peer consecutive ICMP-unreachable errors in sendErrCount.
//   - On sendErrThreshold (3) consecutive matching errors, flip the
//     peer to relay mode immediately (relayPeers[nodeID] = true).
//   - Reset the counter on any inbound successful decrypt from the
//     peer (proof they're alive again — clearRelayOnDirect path will
//     take it from there).
//
// Platform note: macOS does not surface ICMP errors on unconnected UDP
// sockets without IP_RECVERR (Linux-only). The integration path is
// Linux-only in production; the unit test below exercises
// handleSendError directly with a synthesized ECONNREFUSED, which is
// portable across both platforms.
//
// This test pins the CURRENT (buggy) behavior: handleSendError is a
// stub, sendErrCount stays 0, peer stays out of relayPeers no matter
// how many errors we feed in. After GREEN, the assertion flips: 3
// consecutive ECONNREFUSED → relay flip.
func TestICMPUnreachableIgnoredByWriteFrame(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0x11223344
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	tm.mu.Lock()
	tm.peers[peerNodeID] = peerAddr
	tm.mu.Unlock()

	icmpErr := &net.OpError{
		Op:   "write",
		Net:  "udp",
		Addr: peerAddr,
		Err:  syscall.ECONNREFUSED,
	}
	if !errors.Is(icmpErr, syscall.ECONNREFUSED) {
		t.Fatalf("synthesized error doesn't satisfy errors.Is(syscall.ECONNREFUSED): %v", icmpErr)
	}

	// Feed 5 consecutive ICMP-unreachable errors — well over any
	// reasonable threshold. The stub does nothing.
	for i := 0; i < 5; i++ {
		tm.handleSendError(peerNodeID, icmpErr)
	}

	tm.mu.RLock()
	count := tm.sendErrCount[peerNodeID]
	flipped := tm.relayPeers[peerNodeID]
	tm.mu.RUnlock()

	if count != 0 {
		t.Fatalf("BUG NOT REPRODUCED: stub already counts errors (count=%d); GREEN flips this", count)
	}
	if flipped {
		t.Fatalf("BUG NOT REPRODUCED: stub already flips to relay; GREEN flips this")
	}
}

// TestSendErrCountClearedOnPeerRemoval pins the lifecycle invariant
// that already lands in RED: removing a peer wipes their sendErrCount
// entry, preventing stale counts from triggering a phantom flip if the
// peer is later re-admitted with the same nodeID.
func TestSendErrCountClearedOnPeerRemoval(t *testing.T) {
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })

	const peerNodeID uint32 = 0x55667788
	tm.mu.Lock()
	tm.peers[peerNodeID] = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	tm.sendErrCount[peerNodeID] = 7 // simulated stale count
	tm.mu.Unlock()

	tm.RemovePeer(peerNodeID)

	tm.mu.RLock()
	_, present := tm.sendErrCount[peerNodeID]
	tm.mu.RUnlock()
	if present {
		t.Errorf("expected sendErrCount cleared after RemovePeer; entry still present")
	}
}
