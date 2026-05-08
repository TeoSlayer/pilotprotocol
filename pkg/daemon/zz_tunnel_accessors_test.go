// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
)

func TestEnableEncryptionSetsFlagAndGenerates32BytePubKey(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if tm.encrypt {
		t.Fatalf("encrypt flag should default false")
	}

	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if !tm.encrypt {
		t.Fatalf("encrypt flag should be true after EnableEncryption")
	}
	if len(tm.pubKey) != 32 {
		t.Fatalf("pubKey len = %d, want 32 (X25519)", len(tm.pubKey))
	}
	if tm.privKey == nil {
		t.Fatalf("privKey should be populated")
	}
}

func TestEnableEncryptionSecondCallGeneratesFreshKey(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("first EnableEncryption: %v", err)
	}
	pub1 := append([]byte(nil), tm.pubKey...)

	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("second EnableEncryption: %v", err)
	}
	pub2 := tm.pubKey

	if len(pub1) != 32 || len(pub2) != 32 {
		t.Fatalf("pubKey lens = %d, %d; want 32", len(pub1), len(pub2))
	}
	same := true
	for i := range pub1 {
		if pub1[i] != pub2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatalf("second EnableEncryption should generate a different X25519 key")
	}
}

func TestSetNodeIDAndLoadNodeIDRoundTrip(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if got := tm.loadNodeID(); got != 0 {
		t.Fatalf("fresh loadNodeID = %d, want 0", got)
	}

	tm.SetNodeID(0xDEADBEEF)
	if got := tm.loadNodeID(); got != 0xDEADBEEF {
		t.Fatalf("loadNodeID after SetNodeID = %x, want 0xDEADBEEF", got)
	}

	tm.SetNodeID(42)
	if got := tm.loadNodeID(); got != 42 {
		t.Fatalf("loadNodeID after overwrite = %d, want 42", got)
	}
}

func TestSetIdentityAssignsUnderLock(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	tm.SetIdentity(id)

	// Identity now lives under keyexchange.Manager; tm.SetIdentity forwards
	// to it. Read-back via the accessor.
	got := tm.kx.Identity()
	if got != id {
		t.Fatalf("identity not assigned: got %p want %p", got, id)
	}
}

func TestSetBeaconAddrValidAddressStoresResolvedAddr(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.SetBeaconAddr("127.0.0.1:9001"); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	a := tm.routing.BeaconAddr()
	if a == nil {
		t.Fatalf("beaconAddr should be non-nil after valid SetBeaconAddr")
	}
	if a.Port != 9001 {
		t.Fatalf("beaconAddr.Port = %d, want 9001", a.Port)
	}
}

func TestSetBeaconAddrInvalidAddressReturnsErrorAndLeavesPrevious(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.SetBeaconAddr("127.0.0.1:8080"); err != nil {
		t.Fatalf("SetBeaconAddr valid prep: %v", err)
	}
	prev := tm.routing.BeaconAddr()

	if err := tm.SetBeaconAddr("not-a-valid-addr"); err == nil {
		t.Fatalf("expected error for invalid addr, got nil")
	}

	cur := tm.routing.BeaconAddr()
	if cur != prev {
		t.Fatalf("beaconAddr should not be replaced on error: prev=%p cur=%p", prev, cur)
	}
}

func TestSetRelayPeerAndIsRelayPeer(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if tm.IsRelayPeer(7) {
		t.Fatalf("fresh TunnelManager: IsRelayPeer(7) should be false")
	}

	tm.SetRelayPeer(7, true)
	if !tm.IsRelayPeer(7) {
		t.Fatalf("after SetRelayPeer(7,true): IsRelayPeer(7) should be true")
	}

	tm.SetRelayPeer(7, false)
	if tm.IsRelayPeer(7) {
		t.Fatalf("after SetRelayPeer(7,false): IsRelayPeer(7) should be false")
	}
}

func TestRelayPeerIDsReturnsOnlyTrueFlaggedPeers(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if ids := tm.RelayPeerIDs(); len(ids) != 0 {
		t.Fatalf("fresh: RelayPeerIDs = %v, want empty", ids)
	}

	tm.SetRelayPeer(1, true)
	tm.SetRelayPeer(2, false)
	tm.SetRelayPeer(3, true)
	tm.SetRelayPeer(4, false)

	got := tm.RelayPeerIDs()
	set := map[uint32]bool{}
	for _, id := range got {
		set[id] = true
	}
	if len(got) != 2 || !set[1] || !set[3] {
		t.Fatalf("RelayPeerIDs = %v, want {1,3}", got)
	}
	if set[2] || set[4] {
		t.Fatalf("RelayPeerIDs should exclude false-flagged peers, got %v", got)
	}
}
