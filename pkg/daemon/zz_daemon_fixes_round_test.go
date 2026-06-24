// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// --- #1 CmdCancel actually aborts in-flight dials --------------------------

// TestCmdCancelAbortsInFlightDials verifies CmdCancel is no longer a no-op:
// it fires every in-flight dial cancel for the sending IPC connection via
// cancelAllDials, without tearing the connection down.
//
// Before the fix, the read loop did `if cmd == CmdCancel { continue }` and a
// driver that had timed out left the daemon grinding the full dial retry
// budget. The wire envelope carries no per-request token, so cancellation is
// necessarily all-of-this-client's-dials — which matches the cmd's intent.
func TestCmdCancelAbortsInFlightDials(t *testing.T) {
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	ic := newIPCConn(serverConn, 0, false)
	t.Cleanup(func() { ic.Close() })

	// Register two in-flight dial contexts, as handleDial would.
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	ic.addDialCancel(cancel1)
	ic.addDialCancel(cancel2)

	if ic.dialCancelCount() != 2 {
		t.Fatalf("dialCancelCount = %d, want 2 before cancel", ic.dialCancelCount())
	}

	// This is exactly what the CmdCancel branch in handleClient does.
	n := ic.cancelAllDials()
	if n != 2 {
		t.Fatalf("cancelAllDials returned %d, want 2", n)
	}

	// Both dial contexts must now be cancelled.
	for i, ctx := range []context.Context{ctx1, ctx2} {
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("dial ctx %d not cancelled by CmdCancel", i+1)
		}
	}

	// Map is cleared; the IPC connection itself is NOT closed.
	if ic.dialCancelCount() != 0 {
		t.Fatalf("dialCancelCount = %d, want 0 after cancelAllDials", ic.dialCancelCount())
	}
	select {
	case <-ic.done:
		t.Fatal("CmdCancel must not close the IPC connection")
	default:
	}
}

// --- #5 network-ID JSON bounds validation ----------------------------------

func TestNetworkIDFromJSONBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		in     any
		wantID uint16
		wantOK bool
	}{
		{"zero", float64(0), 0, true},
		{"max", float64(65535), 65535, true},
		{"mid", float64(4096), 4096, true},
		{"overflow_wraps_to_1", float64(65537), 0, false},
		{"way_over", float64(1 << 20), 0, false},
		{"negative", float64(-1), 0, false},
		{"fractional", float64(12.5), 0, false},
		{"not_a_number", "12", 0, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := networkIDFromJSON(tc.in)
			if ok != tc.wantOK || got != tc.wantID {
				t.Fatalf("networkIDFromJSON(%v) = (%d,%v), want (%d,%v)",
					tc.in, got, ok, tc.wantID, tc.wantOK)
			}
		})
	}
}

// TestNetworkIDFromBusPayloadBounds confirms the bus-payload extractor
// rejects out-of-range numeric forms instead of silently wrapping them.
func TestNetworkIDFromBusPayloadBounds(t *testing.T) {
	t.Parallel()
	if _, ok := networkIDFromBusPayload(map[string]any{"network_id": float64(70000)}); ok {
		t.Fatal("float64 70000 should be rejected, not wrapped")
	}
	if _, ok := networkIDFromBusPayload(map[string]any{"network_id": int(-5)}); ok {
		t.Fatal("int -5 should be rejected")
	}
	if _, ok := networkIDFromBusPayload(map[string]any{"network_id": int64(1 << 17)}); ok {
		t.Fatal("int64 131072 should be rejected")
	}
	got, ok := networkIDFromBusPayload(map[string]any{"network_id": uint16(42)})
	if !ok || got != 42 {
		t.Fatalf("uint16 42 = (%d,%v), want (42,true)", got, ok)
	}
	got, ok = networkIDFromBusPayload(map[string]any{"network_id": float64(7)})
	if !ok || got != 7 {
		t.Fatalf("float64 7 = (%d,%v), want (7,true)", got, ok)
	}
}

// --- #6 health is purely local ---------------------------------------------

// TestHealthSnapshotIsLocalAndDoesNotTouchRegistry verifies HealthSnapshot
// returns from a daemon with NO registry wired (regConn == nil). Before the
// fix, health went through Info()→nodeNetworks()→regConn.Lookup, so a slow
// or absent registry degraded local health. HealthSnapshot must read only
// in-memory state.
func TestHealthSnapshotIsLocalAndDoesNotTouchRegistry(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // regConn, handshakes, webhook all nil
	d.startTime = time.Now().Add(-3 * time.Second)

	done := make(chan HealthSnapshot, 1)
	go func() { done <- d.HealthSnapshot() }()

	select {
	case h := <-done:
		if h.Uptime < time.Second {
			t.Fatalf("uptime = %v, want >= 1s", h.Uptime)
		}
	case <-time.After(time.Second):
		t.Fatal("HealthSnapshot blocked — it must be purely local (no registry call)")
	}
}

// TestHandleHealthSucceedsWithNilRegistry exercises the IPC handler with no
// registry at all: it must still produce a CmdHealthOK reply. With the old
// Info()-backed implementation this path would have nil-paniced or stalled
// on the registry.
func TestHandleHealthSucceedsWithNilRegistry(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.startTime = time.Now().Add(-2 * time.Second)
	s := d.ipc

	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleHealth(ic, 0) })
	if len(reply) == 0 || reply[0] != CmdHealthOK {
		t.Fatalf("reply opcode = %v, want CmdHealthOK", reply)
	}
}

// --- #8 pending KX queue drops NEWEST, preserving the ordered prefix -------

// TestPendingQueueDropsNewestPreservesPrefix verifies that when the per-peer
// pending key-exchange queue is full, the daemon drops the NEWEST frame (the
// incoming one) rather than the oldest. flushPending replays FIFO, so the
// oldest frames are the connection-setup prefix (SYN, first app bytes);
// dropping the head would strand the receiver's in-order reassembly, whereas
// a dropped tail segment is recovered by the transport retransmit layer.
func TestPendingQueueDropsNewestPreservesPrefix(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	tm.SetNodeID(5)

	peerConn := mustListenUDP(t)
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	const nodeID = 77

	// Seed the queue to capacity with identifiable sentinel frames. The head
	// sentinel represents the ordered-prefix first bytes we must preserve.
	head := []byte("HEAD-FIRST-BYTES")
	tm.pendMu.Lock()
	q := make([][]byte, 0, maxPendingPerPeer)
	q = append(q, head)
	for i := 1; i < maxPendingPerPeer; i++ {
		q = append(q, []byte{byte(i)})
	}
	tm.pending[nodeID] = q
	tm.pendMu.Unlock()

	dropsBefore := tm.PendingDrops

	// One more send while the queue is full. Mark the peer endpoint so the
	// send path enqueues (encryption on, key exchange not yet complete).
	tm.AddPeer(nodeID, peerAddr)
	overflow := newPacket("OVERFLOW-NEWEST")
	err := tm.SendTo(peerAddr, nodeID, overflow)
	if err == nil {
		t.Fatal("expected ErrPendingDropped when queue is full, got nil")
	}

	tm.pendMu.Lock()
	got := tm.pending[nodeID]
	tm.pendMu.Unlock()

	// Queue must stay capped — the newest packet was rejected, not appended.
	if len(got) != maxPendingPerPeer {
		t.Fatalf("queue len = %d, want %d (newest must be dropped, not appended)",
			len(got), maxPendingPerPeer)
	}
	// The ordered prefix (head) must be intact at position 0.
	if !bytes.Equal(got[0], head) {
		t.Fatalf("head frame was dropped — ordered prefix not preserved; got[0]=%x", got[0])
	}
	// The overflow payload must NOT be anywhere in the queue.
	for i, f := range got {
		if bytes.Contains(f, []byte("OVERFLOW-NEWEST")) {
			t.Fatalf("overflow frame should have been dropped but found at index %d", i)
		}
	}
	if tm.PendingDrops != dropsBefore+1 {
		t.Fatalf("PendingDrops = %d, want %d", tm.PendingDrops, dropsBefore+1)
	}
}

// --- #3 UDP reachability requires positive evidence ------------------------

// TestProbeUDPReachableNoReplyReturnsFalse verifies the reachability probe
// returns false when nothing answers the beacon discover within the window.
// A silently-dropped/blackholed UDP path (the common UDP-blocked corporate
// case) produces no reply; treating that as reachable was the bug that kept
// UDP-blocked nets from auto-switching to compat. We point the probe at a
// TEST-NET-1 (RFC 5737) address that is guaranteed not to answer.
func TestProbeUDPReachableNoReplyReturnsFalse(t *testing.T) {
	t.Parallel()
	// 192.0.2.0/24 is reserved for documentation/tests and routes nowhere.
	if probeUDPReachable("192.0.2.1:9001") {
		t.Fatal("probeUDPReachable must be false when no beacon reply arrives (no-evidence-of-UDP)")
	}
}

// TestProbeUDPReachableBadAddrReturnsFalse covers the malformed-input guard.
func TestProbeUDPReachableBadAddrReturnsFalse(t *testing.T) {
	t.Parallel()
	if probeUDPReachable("not-a-host-port") {
		t.Fatal("malformed beacon addr must yield false")
	}
}
