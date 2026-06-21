// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

import (
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

func TestManagerGettersAndSetters(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)

	// PubKey is empty until SetIdentity runs — covers the nil-key branch.
	if pk := m.PubKey(); pk != nil {
		t.Errorf("PubKey() on fresh manager = %v, want nil", pk)
	}

	// SetPreRetransmitHook accepts a closure and stores it (no observable
	// state to assert beyond not panicking).
	called := false
	m.SetPreRetransmitHook(func(peerNodeID uint32, attempt int) {
		called = true
	})
	_ = called // hook only fires via the rekey loop; just exercise the setter.

	// Local node ID closure is allowed to be nil; setter just records.
	m.SetLocalNodeIDFn(func() uint32 { return 0xCAFE })
}

func TestPendingRekeyHelpers(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)
	const peer uint32 = 0x1234

	// PeerInRekeyGaveUp on a fresh manager is always false.
	if m.PeerInRekeyGaveUp(peer) {
		t.Errorf("fresh manager: PeerInRekeyGaveUp(%d) = true, want false", peer)
	}

	// PendingRekeyForTest returns nil for an unknown peer.
	if st := m.PendingRekeyForTest(peer); st != nil {
		t.Errorf("PendingRekeyForTest(%d) on fresh = %v, want nil", peer, st)
	}

	// InjectPendingRekeyForTest seeds a state; ResetPendingRekeyAttempts zeroes it.
	m.InjectPendingRekeyForTest(peer, &keyexchange.PendingRekeyState{
		Attempts:   4,
		LastSentAt: time.Now(),
	})
	if st := m.PendingRekeyForTest(peer); st == nil || st.Attempts != 4 {
		t.Fatalf("after Inject: %v", st)
	}
	if got := m.PendingRekeyAttempts(peer); got != 4 {
		t.Errorf("PendingRekeyAttempts = %d, want 4", got)
	}
	m.ResetPendingRekeyAttempts(peer)
	if st := m.PendingRekeyForTest(peer); st != nil && st.Attempts != 0 {
		t.Errorf("after Reset: attempts = %d, want 0", st.Attempts)
	}
}

func TestClearRekeyGaveUp(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)
	const peer uint32 = 0x5678
	// Sanity: clearing an absent entry is a no-op.
	m.ClearRekeyGaveUp(peer)
	if m.PeerInRekeyGaveUp(peer) {
		t.Errorf("after clearing absent peer: PeerInRekeyGaveUp = true")
	}
}
