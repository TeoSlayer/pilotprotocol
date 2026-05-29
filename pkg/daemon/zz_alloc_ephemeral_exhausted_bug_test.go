// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// TestAllocEphemeralPortReturnsZeroOnUInt16Overflow verifies that
// AllocEphemeralPort returns 0 as an intentional exhaustion sentinel
// (not via uint16 overflow) when all 16384 ephemeral ports are in use,
// and that nextEphPort stays within the ephemeral range afterward.
//
// Bug (pre-v1.9.1): when all 16384 ephemeral ports (49152..65535) were in
// use, `nextEphPort++` on value 65535 silently overflowed to 0 (uint16
// arithmetic). The subsequent `> PortEphemeralMax` check failed (0 > 65535
// is false), so the wrap-to-MIN never fired. The next iteration found
// port=0 not in use and returned it — a non-ephemeral port that collides
// with PortPing. After the call, nextEphPort was stuck at 1, outside the
// ephemeral range.
//
// Fix (v1.9.1): AllocEphemeralPort uses a bounded int counter (max 16384
// iterations) and checks `>= PortEphemeralMax` BEFORE the increment, so
// nextEphPort never escapes the ephemeral range. Exhaustion is signaled
// by returning 0 intentionally. Callers (dialConnectionLocked,
// SendDatagram, BroadcastDatagram) now check for 0 and return
// ErrEphemeralExhausted rather than silently proceeding with port=0.
//
// GREEN assertion: after an exhaustion call, nextEphPort must still be
// in [PortEphemeralMin, PortEphemeralMax]. The overflow bug left it at 1
// (or some value in [0..PortEphemeralMin-1]), making this check fail
// against the unpatched code.
func TestAllocEphemeralPortReturnsZeroOnUInt16Overflow(t *testing.T) {
	t.Parallel()
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

	// FIXED: returns 0 as an intentional exhaustion sentinel.
	if got != 0 {
		t.Fatalf("expected 0 (exhaustion sentinel) when all ephemeral ports are in use; got %d", got)
	}

	// GREEN distinguisher: nextEphPort must be within the ephemeral range
	// after the exhaustion scan. The overflow bug left nextEphPort at 1
	// (uint16 wrapped past 65535 → 0 → loop continued → nextEphPort=1).
	pm.mu.Lock()
	next := pm.nextEphPort
	pm.mu.Unlock()
	if next < protocol.PortEphemeralMin || next > protocol.PortEphemeralMax {
		t.Errorf("nextEphPort=%d escaped ephemeral range [%d..%d] — uint16 overflow fix not applied",
			next, protocol.PortEphemeralMin, protocol.PortEphemeralMax)
	}
}
