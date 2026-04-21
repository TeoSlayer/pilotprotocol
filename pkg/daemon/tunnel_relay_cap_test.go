package daemon

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestHandleRelayDeliverCapsRelayPeers confirms that beacon-relayed packets
// cannot grow the relayPeers map past maxRelayPeers. The srcNodeID in a relay
// delivery is attacker-controlled; without a cap, each unique spoofed ID would
// add a relayPeers entry, a peers alias, and fire a "tunnel.relay_activated"
// webhook.
func TestHandleRelayDeliverCapsRelayPeers(t *testing.T) {
	tm := NewTunnelManager()
	tm.beaconAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}

	// Pre-seed the cap with distinct live entries so the next relay packet
	// with a fresh srcNodeID must be dropped.
	for i := uint32(1); i <= maxRelayPeers; i++ {
		tm.relayPeers[i] = true
	}

	// Construct a minimal relay frame: [srcNodeID(4)][inner payload...]. The
	// inner payload is shorter than 4 bytes so the magic-byte switch bails —
	// this test focuses solely on the cap, not inner dispatch.
	var buf [4]byte
	intruderID := uint32(0xDEADBEEF)
	binary.BigEndian.PutUint32(buf[:], intruderID)

	tm.handleRelayDeliver(buf[:])

	tm.mu.Lock()
	_, present := tm.relayPeers[intruderID]
	size := len(tm.relayPeers)
	_, peerPresent := tm.peers[intruderID]
	tm.mu.Unlock()

	if present {
		t.Fatal("spoofed srcNodeID must not be added once cap is hit")
	}
	if peerPresent {
		t.Fatal("peers map must not alias beacon addr for dropped relay packet")
	}
	if size != maxRelayPeers {
		t.Fatalf("relayPeers size=%d, want %d (unchanged)", size, maxRelayPeers)
	}
}
