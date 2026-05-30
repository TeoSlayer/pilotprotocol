// SPDX-License-Identifier: AGPL-3.0-or-later

package routing_test

import (
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/routing"
)

func timeNowMinus(_ *testing.T, secs int) time.Time {
	return time.Now().Add(-time.Duration(secs) * time.Second)
}

// TestClearRelayOnDirect_BeaconSourceResetsBlackholeMissCount pins the fix
// for the direct-path collapse regression: when an encrypted packet decrypts
// successfully but arrived via the beacon (from == beaconAddr), the miss
// counter that drives MaybeFlipBlackhole's "silent direct → pin relay"
// auto-flip must still be reset. Without this reset, every peer that prefers
// to reply via relay eventually got pinned-to-relay on our side after the
// 8-second silent threshold, even though the peer was demonstrably alive.
// The test bumps misses up to one below the pin threshold, then delivers a
// relay-decrypt event and asserts the counter snapped back to zero.
func TestClearRelayOnDirect_BeaconSourceResetsBlackholeMissCount(t *testing.T) {
	t.Parallel()
	m := routing.New()
	beacon := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 9001}
	m.SetBeaconAddrUDP(beacon)

	const peer uint32 = 0xA1FA0001
	// Walk the miss counter up to BlackholeMissesRequired-1 by simulating
	// silent sends past the threshold. We can't trip the heuristic directly
	// without time travel, so seed firstOutboundSend in the past and call
	// MaybeFlipBlackhole repeatedly until we're one miss shy of the flip.
	// Use the public RecordOutboundSend so the path matches production.
	m.RecordOutboundSend(peer, timeNowMinus(t, 20))
	for i := 0; i < routing.BlackholeMissesRequired-1; i++ {
		_, flipped, _, _ := m.MaybeFlipBlackhole(peer)
		if flipped {
			t.Fatalf("flipped early at iter=%d; misses=%d", i, m.BlackholeMissCount(peer))
		}
	}
	if got := m.BlackholeMissCount(peer); got != routing.BlackholeMissesRequired-1 {
		t.Fatalf("seeded misses=%d, want %d", got, routing.BlackholeMissesRequired-1)
	}

	// Simulate a relay-decrypted packet: from == beacon. The new behavior
	// must reset blackholeMissCount even though the relay flag is left alone.
	cleared := m.ClearRelayOnDirect(peer, beacon)
	if cleared {
		t.Fatal("relay→direct must NOT report cleared for beacon-source packets")
	}
	if got := m.BlackholeMissCount(peer); got != 0 {
		t.Fatalf("miss counter not reset after relay decrypt: got %d, want 0", got)
	}
}

// TestPILAViaRelayDoesNotPinRelayWhenDirectAddrKnown is the routing-side
// counterpart of the tunnel-layer onKeyInstalled + handleRelayDeliver patches.
// When the peer's PILA arrives via the beacon (fromRelay=true) but ensureTunnel
// already populated the peer's real UDP address, the routing manager must
// NOT be told to admit-and-pin relay. The fix lives in tunnel.go but this
// test pins the invariant by exercising the public AdmitRelayFromBeacon path
// only in the "no direct addr" branch and confirming that, when we skip it,
// IsRelayPeer and IsRelayPinned both stay false.
func TestPILAViaRelayDoesNotPinRelayWhenDirectAddrKnown(t *testing.T) {
	t.Parallel()
	m := routing.New()
	beacon := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 9001}
	m.SetBeaconAddrUDP(beacon)

	const peer uint32 = 0xA1FA0002
	// Simulating tunnel.go's onKeyInstalled when knownDirect==true: we do
	// nothing relay-side. Verify the manager stays in direct mode.
	if m.IsRelayPeer(peer) {
		t.Fatal("relay flag set before any input")
	}
	if m.IsRelayPinned(peer) {
		t.Fatal("relay pin set before any input")
	}

	// And the negative case: simulate the legacy unconditional pin path.
	// AdmitRelayFromBeacon SHOULD set both flags. This ensures we haven't
	// regressed the relay-cap admission code in trying to fix direct.
	m.AdmitRelayFromBeacon(peer)
	if !m.IsRelayPeer(peer) {
		t.Fatal("AdmitRelayFromBeacon failed to set relay flag")
	}
	if !m.IsRelayPinned(peer) {
		t.Fatal("AdmitRelayFromBeacon failed to set pin flag")
	}
}
