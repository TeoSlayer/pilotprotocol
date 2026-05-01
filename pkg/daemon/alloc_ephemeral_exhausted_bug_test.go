// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestAllocEphemeralPortReturnsZeroOnUInt16Overflow reproduces the
// "exhausted ephemeral range falls through uint16 overflow into
// non-ephemeral port 0" bug.
//
// Symptom: AllocEphemeralPort scans 49152..65535 (the ephemeral
// range) looking for an unused port. When ALL 16384 ports are in
// use, the loop is supposed to wrap. The current code:
//
//	for {
//	    port := pm.nextEphPort
//	    pm.nextEphPort++
//	    if pm.nextEphPort > protocol.PortEphemeralMax {
//	        pm.nextEphPort = protocol.PortEphemeralMin
//	    }
//	    if !pm.portInUse(port) { return port }
//	    if pm.nextEphPort == start { return port }
//	}
//
// Because pm.nextEphPort is uint16, `nextEphPort++` on 65535
// silently overflows to 0 BEFORE the `> PortEphemeralMax` wrap
// check. 0 > 65535 is false, so the wrap-to-MIN doesn't fire.
// nextEphPort stays at 0, which is OUTSIDE the ephemeral range.
// The next loop iteration tries port=0, finds it not in
// pm.connections (since we never use port 0 — PortPing is reserved),
// and returns 0.
//
// The caller (DialConnection's localPort assignment) then proceeds
// with port=0, creating a Connection that:
//   - violates the ephemeral-port range invariant
//   - collides with PortPing (reserved port 0)
//   - looks like a control-plane port to peers that route based
//     on well-known port numbers
//
// Real-world impact: pathological accumulation of stuck SYN_SENT
// or half-closed connections (e.g. a peer that ignored every FIN,
// leaving us in StateFinWait until idleSweepLoop reaps) plus high
// dial volume could exhaust the ephemeral range. Hard to hit in
// normal use, but silent corruption when it happens.
//
// What the v1.9.1 fix should change: AllocEphemeralPort detects
// real exhaustion (no available port in the ephemeral range) and
// returns a sentinel value with a callable error path. Callers
// (DialConnectionContext, SendDatagram, BroadcastDatagram) check
// the result and surface a clear "ephemeral ports exhausted"
// error rather than silently proceeding with port=0.
//
// This test pins the CURRENT (buggy) behavior: pre-fill all 16384
// ephemeral ports with active connections, call AllocEphemeralPort,
// observe that it returns 0 (a non-ephemeral port). After GREEN,
// the assertion flips: returns the ErrEphemeralExhausted sentinel
// or surfaces an error.
func TestAllocEphemeralPortReturnsZeroOnUInt16Overflow(t *testing.T) {
	pm := NewPortManager()

	// Pre-fill every ephemeral port with an active connection. The
	// connection map is keyed by ID, not LocalPort — portInUse
	// iterates values and matches LocalPort. Use uint32(p) as the
	// ID so each entry is unique.
	for p := int(protocol.PortEphemeralMin); p <= int(protocol.PortEphemeralMax); p++ {
		port := uint16(p)
		pm.connections[uint32(port)] = &Connection{
			ID:        uint32(port),
			LocalPort: port,
			State:     StateEstablished,
		}
	}

	got := pm.AllocEphemeralPort()

	// CURRENT (buggy) behavior: returns 0 — a non-ephemeral port
	// that collides with reserved PortPing. The uint16 overflow on
	// nextEphPort++ from 65535 wraps to 0, the > PortEphemeralMax
	// wrap-check doesn't fire, and the next iteration finds port=0
	// not in use (no entries claim it).
	if got != 0 {
		// Either the bug is fixed (got is in the ephemeral range), or
		// got is some other non-ephemeral port. Anything other than 0
		// means the test scenario didn't reproduce the specific overflow.
		if got >= protocol.PortEphemeralMin && got <= protocol.PortEphemeralMax {
			t.Fatalf("BUG NOT REPRODUCED: got %d in ephemeral range (fix may be in place); GREEN flips this", got)
		}
		t.Fatalf("got unexpected non-ephemeral port %d (expected 0 from overflow path)", got)
	}
	t.Logf("AllocEphemeralPort returned port 0 — outside ephemeral range (49152..65535), collides with PortPing")
}
