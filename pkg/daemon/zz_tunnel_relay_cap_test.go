// SPDX-License-Identifier: AGPL-3.0-or-later

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
	t.Parallel()
	tm := NewTunnelManager()
	tm.routing.SetBeaconAddrUDP(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001})

	// Pre-seed the cap with distinct live entries so the next relay packet
	// with a fresh srcNodeID must be dropped. We also need crypto context
	// for those nodes to have hadCrypto=true on relay-deliver — but that's
	// orthogonal here: the cap check fires regardless of hadCrypto. We
	// drive admission via the helper to seed each entry as a live relay
	// peer.
	for i := uint32(1); i <= maxRelayPeers; i++ {
		tm.routing.SetRelayPeer(i, true)
	}

	// Install crypto for the intruder's spoofed ID so hadCrypto=true and
	// the cap-check path runs (otherwise the function admits without
	// adding to the map).
	intruderID := uint32(0xDEADBEEF)
	tm.envelope.Install(intruderID, &peerCrypto{Ready: true})

	// Construct a minimal relay frame: [srcNodeID(4)][inner payload...]. The
	// inner payload is shorter than 4 bytes so the magic-byte switch bails —
	// this test focuses solely on the cap, not inner dispatch.
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], intruderID)

	tm.handleRelayDeliver(buf[:])

	present := tm.routing.IsRelayPeer(intruderID)
	size := tm.routing.RelayPeerCount()
	tm.mu.Lock()
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
