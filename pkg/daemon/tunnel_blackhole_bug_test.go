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
//  1. Skip the flip if conn-level retransmit budget hasn't been
//     exhausted (direct path is actively being used; absence of recv
//     ACK means the peer is slow, not unreachable).
//  2. Require N consecutive 8 s gaps WITH active sends in between
//     (transient pause shouldn't latch the relay flag).
//  3. Raise the threshold (30 s+) under normal load and only drop
//     it when the application explicitly requests fast-failover.
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

	// One frame send used to be enough to trigger the heuristic. With
	// the v1.9.1 hysteresis fix, a single window now only increments
	// the miss counter; the flip itself requires blackholeMissesRequired
	// consecutive observations.
	frame := []byte{0x50, 0x49, 0x4c, 0x54, 0x00, 0x00, 0x00, 0x42, 'p', 'a', 'y'}
	addr := peerConn.LocalAddr().(*net.UDPAddr)
	if err := d.tunnels.writeFrame(peerNode, addr, frame); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}

	// FIXED (v1.9.1): single transient 9 s gap MUST NOT flip. The
	// heuristic now requires N consecutive misses, dampening transient
	// ACK gaps caused by GC pauses, scheduler jitter, or brief packet
	// reordering. This is the regression target for the bench
	// bimodality (4 MB/s ↔ 0.06 MB/s) seen in the autoscale run.
	d.tunnels.mu.RLock()
	flipped := d.tunnels.relayPeers[peerNode]
	misses := d.tunnels.blackholeMissCount[peerNode]
	d.tunnels.mu.RUnlock()
	if flipped {
		t.Errorf("did not expect relay flip on single transient 9 s gap (v1.9.1 hysteresis); got flipped=true")
	}
	if misses != 1 {
		t.Errorf("expected blackholeMissCount=1 after one observation; got %d", misses)
	}
}

// TestWriteFrameFlipsToRelayAfterSustainedBlackhole pins the OTHER
// half of the hysteresis: the heuristic still flips when the
// blackhole is REAL (multiple consecutive 8+ s gaps with verified
// outbound sends in between). Without this property pinned, a
// future "raise the threshold" change could accidentally disable
// the recovery path entirely.
func TestWriteFrameFlipsToRelayAfterSustainedBlackhole(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFE0BAD
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	beacon, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("beacon listen: %v", err)
	}
	t.Cleanup(func() { beacon.Close() })
	if err := d.tunnels.SetBeaconAddr(beacon.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	frame := []byte{0x50, 0x49, 0x4c, 0x54, 0x00, 0x00, 0x00, 0x42, 'p', 'a', 'y'}
	addr := peerConn.LocalAddr().(*net.UDPAddr)

	// Drive blackholeMissesRequired (3) consecutive observations of
	// staleness. Reset the lastDirectRecv timestamp before each call
	// so the threshold check fires every time. Real production
	// traffic gets the same effect over a longer wall-clock window.
	for i := 0; i < blackholeMissesRequired; i++ {
		d.tunnels.mu.Lock()
		d.tunnels.lastDirectRecv[peerNode] = time.Now().Add(-9 * time.Second)
		d.tunnels.mu.Unlock()
		if err := d.tunnels.writeFrame(peerNode, addr, frame); err != nil {
			t.Fatalf("writeFrame iter %d: %v", i, err)
		}
	}

	d.tunnels.mu.RLock()
	flipped := d.tunnels.relayPeers[peerNode]
	d.tunnels.mu.RUnlock()
	if !flipped {
		t.Errorf("expected relay flip after %d consecutive blackhole observations; got flipped=false",
			blackholeMissesRequired)
	}
}

// TestRelayAutoClearDisabled pins the v1.9.1-rc2 behavior: the
// relay→direct auto-clear heuristic is disabled. Any number of
// "direct" packet receipts must NOT clear the relay flag — only an
// explicit operator action (SetRelayPeer with relay=false) does.
//
// Background: the previous heuristic (3 consecutive non-beacon
// packets → clear) was unreliable in production environments with
// NAT-port-rewrite or beacon-mesh forwarding, where a packet from
// the beacon could be observed with a non-matching source IP/port
// and trigger a spurious clear. The clear caused a 60-180 second
// "ping works for a minute then dial timeout" symptom as the
// daemon flapped between direct and relay states with each flap
// rotating session keys mid-flight.
func TestRelayAutoClearDisabled(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xC0DEFACE
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4242}

	// Force the peer into relay mode.
	d.tunnels.mu.Lock()
	d.tunnels.relayPeers[peerNode] = true
	d.tunnels.mu.Unlock()

	// Many direct receipts — flag must stay set.
	for i := 0; i < 50; i++ {
		d.tunnels.mu.Lock()
		cleared := d.tunnels.clearRelayOnDirectLocked(peerNode, peerAddr)
		d.tunnels.mu.Unlock()
		if cleared {
			t.Fatalf("auto-clear must be disabled but cleared=true on receipt #%d", i+1)
		}
	}
	d.tunnels.mu.RLock()
	stillRelay := d.tunnels.relayPeers[peerNode]
	d.tunnels.mu.RUnlock()
	if !stillRelay {
		t.Fatal("relay flag must remain set after 50 direct receipts; got cleared")
	}

	// Explicit operator clear via SetRelayPeer must still work.
	d.tunnels.SetRelayPeer(peerNode, false)
	d.tunnels.mu.RLock()
	afterExplicit := d.tunnels.relayPeers[peerNode]
	d.tunnels.mu.RUnlock()
	if afterExplicit {
		t.Fatal("explicit SetRelayPeer(false) must clear the flag")
	}
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
