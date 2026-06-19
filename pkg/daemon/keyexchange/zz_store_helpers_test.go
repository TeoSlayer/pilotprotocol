// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

import (
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

func TestStoreLocalNodeID_RoundTrip(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	if got := s.LocalNodeID(); got != 0 {
		t.Errorf("fresh store: LocalNodeID = %d, want 0", got)
	}
	s.SetLocalNodeID(0xDEADBEEF)
	if got := s.LocalNodeID(); got != 0xDEADBEEF {
		t.Errorf("after Set: LocalNodeID = %x, want DEADBEEF", got)
	}
}

func TestShouldDropOnOutsideWindow_NilCrypto(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	if s.ShouldDropOnOutsideWindow(0x1234, nil) {
		t.Errorf("nil crypto: want false")
	}
}

func TestCryptoUndoReplayBit_NoOp(t *testing.T) {
	t.Parallel()
	c := &keyexchange.Crypto{}
	// UndoReplayBit on a fresh crypto (all-zero bitmap) is a no-op: the bit
	// is already zero and AND-NOT keeps it zero.
	c.UndoReplayBit(7)
	c.UndoReplayBit(123)
	// No observable effect — just verifying it doesn't panic.
}
