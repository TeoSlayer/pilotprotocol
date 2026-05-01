// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"
)

// TestWriteFrameFlipsToRelayOnTransientReceiveGap reproduces the
// "mid-flight blackhole flip" bug.
//
// Symptom: bench traffic from agent A to agent B fluctuates wildly —
// sometimes a 50 MB transfer hits ~4.2 MB/s (steady direct path),
// other times it stalls at ~0.06 MB/s for minutes. The cliff is
// reproducible and not random network loss; it's the daemon flipping
// to relay mid-flight when ACK reception lags by 8+ seconds.
//
// Code path (`pkg/daemon/tunnel.go::writeFrame`):
//
//	if !relay && bAddr != nil && hasRecv && time.Since(lastRecv) > 8*time.Second {
//	    tm.relayPeers[nodeID] = true
//	    slog.Info("direct path silent, flipping to relay", ...)
//	    relay = true
//	}
//
// The condition fires from EVERY outbound send. There's no check for
// whether the sender has unacknowledged in-flight bytes (which would
// indicate the direct path is being actively exercised) and no
// requirement for N consecutive failed windows. A single transient
// ACK gap — common under load, GC pauses, scheduling jitter, or
// brief packet reordering — is enough to flap the entire tunnel
// onto the relay path until "relay→direct auto-cleared on direct
// packet receipt" eventually fires, after which it can flap back.
//
// Real-world impact (observed in this session's autoscale bench):
//   - 50 MB direct transfer iter 1: 4.16 MB/s
//   - 50 MB direct transfer iter 2: 0.09 MB/s  (568 s wall clock)
//   - 50 MB direct transfer iter 3: 4.27 MB/s
//
// What v1.9.x's tunnel-stability fix should change. Any of:
//   1. Skip the flip if conn-level retransmit budget hasn't been
//      exhausted (direct path is actively being used; absence of recv
//      ACK means the peer is slow, not unreachable).
//   2. Require N consecutive 8 s gaps WITH active sends in between
//      (transient pause shouldn't latch the relay flag).
//   3. Raise the threshold (30 s+) under normal load and only drop
//      it when the application explicitly requests fast-failover.
//
// This test pins the CURRENT behavior so the fix has a concrete
// regression target. After the fix, the assertion below flips:
// the relay flag must NOT be set after a single transient gap;
// only after a documented multi-window failure.
func TestWriteFrameFlipsToRelayOnTransientReceiveGap(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEFADE
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	// The flip path requires a beacon address. Point at a real loopback
	// UDP socket (we won't actually relay anything; just need bAddr != nil).
	beacon, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("beacon listen: %v", err)
	}
	t.Cleanup(func() { beacon.Close() })
	if err := d.tunnels.SetBeaconAddr(beacon.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	// Simulate the observed scenario: peer is alive (we received from
	// it before), but the most recent direct recv was just over the
	// 8 s threshold ago. This represents a transient ACK gap, NOT a
	// genuine outage — peer is going to send packets again any moment.
	d.tunnels.mu.Lock()
	d.tunnels.lastDirectRecv[peerNode] = time.Now().Add(-9 * time.Second)
	// Sanity: not already in relay mode.
	if d.tunnels.relayPeers[peerNode] {
		t.Fatal("setup: peer should not start in relay mode")
	}
	d.tunnels.mu.Unlock()

	// One frame send is enough to trigger the heuristic. Content
	// doesn't matter — writeFrame's flip check runs at the top.
	frame := []byte{0x50, 0x49, 0x4c, 0x54, 0x00, 0x00, 0x00, 0x42, 'p', 'a', 'y'}
	addr := peerConn.LocalAddr().(*net.UDPAddr)
	if err := d.tunnels.writeFrame(peerNode, addr, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	// CURRENT BUG: peer flipped to relay on ONE transient 9 s gap.
	// No verification that direct is actually broken; no requirement
	// for repeated misses; the in-flight transfer this writeFrame
	// belongs to will now ride the relay path until the next direct
	// packet from the peer fires the auto-clear.
	d.tunnels.mu.RLock()
	flipped := d.tunnels.relayPeers[peerNode]
	d.tunnels.mu.RUnlock()
	if !flipped {
		t.Errorf("expected relay flip on single transient 9 s ACK gap (current bug); got flipped=false")
	}

	// POST-FIX: replace the assertion above with
	//   if flipped {
	//       t.Errorf("did not expect relay flip on single transient gap; "+
	//                "fix should require multi-window failure or unacked-data drain")
	//   }
	// and add a follow-up test that confirms a SUSTAINED multi-window
	// outage (e.g. 3 × 30 s gaps with verified outbound sends) DOES
	// trigger the flip — that's the legitimate use case the heuristic
	// was originally written for.
}

// TestWriteFrameDoesNotFlipForUnknownPeer documents the (correct)
// guard: peers we've never received from directly are not flipped
// by this heuristic — they go through the slower DialConnection
// auto-switch path instead. This test pins that property so a future
// "more aggressive flip" change doesn't accidentally erase it.
func TestWriteFrameDoesNotFlipForUnknownPeer(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xBAADF00D
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	beacon, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("beacon listen: %v", err)
	}
	t.Cleanup(func() { beacon.Close() })
	_ = d.tunnels.SetBeaconAddr(beacon.LocalAddr().String())

	// Do NOT seed lastDirectRecv — peer is "never heard from directly".
	// The flip guard's `hasRecv` check should prevent the flip.
	frame := []byte{0x50, 0x49, 0x4c, 0x54, 0x00, 0x00, 0x00, 0x42, 'p', 'a', 'y'}
	addr := peerConn.LocalAddr().(*net.UDPAddr)
	if err := d.tunnels.writeFrame(peerNode, addr, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	d.tunnels.mu.RLock()
	flipped := d.tunnels.relayPeers[peerNode]
	d.tunnels.mu.RUnlock()
	if flipped {
		t.Error("flip fired for never-heard-from peer; the hasRecv guard should have blocked it")
	}
}
