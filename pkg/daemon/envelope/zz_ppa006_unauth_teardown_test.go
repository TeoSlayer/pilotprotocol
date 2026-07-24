// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

import (
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/envelope"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// TestForgedOutsideWindowFrameDoesNotTearDownAgedSession is the PPA-006
// regression: a single UNAUTHENTICATED frame carrying an outside-window
// counter must not drive the teardown counters, so it cannot fast-drop a
// settled (>AgedCryptoFastDropAge) session.
func TestForgedOutsideWindowFrameDoesNotTearDownAgedSession(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	advance := keyexchange.ReplayWindowSize + 8
	for i := 0; i < advance; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("advance"))
		if err != nil {
			t.Fatalf("encrypt advance #%d: %v", i, err)
		}
		if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
			t.Fatalf("advance decrypt #%d: %v", i, r.Err)
		}
	}

	c := s.peerStore.Get(s.localID)
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.AgedCryptoFastDropAge))

	res := envelope.DecryptFrame(s.peerStore, forgeFrame(s.localID, 1))
	if !errors.Is(res.Err, envelope.ErrAEAD) {
		t.Fatalf("forged outside-window frame: err=%v, want ErrAEAD", res.Err)
	}

	c.ReplayMu.Lock()
	owc := c.OutsideWindowCount
	rc := c.ReplayCount
	c.ReplayMu.Unlock()
	if owc != 0 {
		t.Fatalf("forged frame bumped OutsideWindowCount to %d; unauthenticated frames must not drive teardown", owc)
	}
	if rc != 0 {
		t.Fatalf("forged frame bumped ReplayCount to %d", rc)
	}
	if s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatalf("aged session torn down by a single unauthenticated frame (PPA-006)")
	}
	if s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatalf("aged session dropped via replay gate by a single unauthenticated frame")
	}
	if s.peerStore.ShouldDropOnDecryptFail(s.localID, c) {
		t.Fatalf("single unauthenticated frame reached the decrypt-fail drop threshold")
	}
}

// TestAuthenticatedOutsideWindowStillTearsDownAgedSession pins that the
// legitimate recovery path is untouched: a GENUINE (authenticated)
// outside-window frame still bumps the counter and trips the aged fast-drop.
func TestAuthenticatedOutsideWindowStillTearsDownAgedSession(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	stale, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("stale"))
	if err != nil {
		t.Fatalf("encrypt stale: %v", err)
	}
	advance := keyexchange.ReplayWindowSize + 8
	for i := 0; i < advance; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("advance"))
		if err != nil {
			t.Fatalf("encrypt advance #%d: %v", i, err)
		}
		if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
			t.Fatalf("advance decrypt #%d: %v", i, r.Err)
		}
	}

	c := s.peerStore.Get(s.localID)
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.AgedCryptoFastDropAge))

	res := envelope.DecryptFrame(s.peerStore, stale[4:])
	if !errors.Is(res.Err, envelope.ErrOutsideWindow) {
		t.Fatalf("genuine stale frame: err=%v, want ErrOutsideWindow", res.Err)
	}
	c.ReplayMu.Lock()
	owc := c.OutsideWindowCount
	c.ReplayMu.Unlock()
	if owc != 1 {
		t.Fatalf("OutsideWindowCount=%d after authenticated outside-window frame; want 1", owc)
	}
	if !s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatalf("aged session with authenticated divergence must still tear down")
	}
}
