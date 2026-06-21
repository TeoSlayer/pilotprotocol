// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

// Regression tests for the outside-replay-window stuck-state bug
// observed in v1.10.0-rc3 against list-agents on 2026-05-11:
//
// list-agents' MaxRecvNonce for our node stayed at 8518 while our
// outbound counter sat at ~400 after a fresh key exchange. Every frame
// we sent was rejected as ErrOutsideWindow. The current code path at
// tunnel.go ErrOutsideWindow case logs and returns — no recovery.
// Tunnel half-dead until a daemon restart on either side.
//
// The fix tracks consecutive outside-window rejections on the Crypto
// (mirroring DecryptFailCount) and surfaces a ShouldDropOnOutsideWindow
// gate that the L7 handler uses to drop + rekey. These tests exercise
// the keyexchange/envelope half of the fix; the tunnel.go wiring is
// covered by integration tests on the daemon.

import (
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/envelope"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// TestOutsideWindowCountIncrementsAndResets pins the bookkeeping: each
// ErrOutsideWindow bumps OutsideWindowCount; a successful decrypt
// resets it to 0. This is the input ShouldDropOnOutsideWindow consumes.
func TestOutsideWindowCountIncrementsAndResets(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// Stash a frame at counter=1.
	stale, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("stale"))
	if err != nil {
		t.Fatalf("encrypt stale: %v", err)
	}

	// Advance peer MaxRecvNonce past ReplayWindowSize+1 by encrypting and
	// delivering fresh frames so stale (counter=1) lands outside the window.
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
	c.ReplayMu.Lock()
	pre := c.OutsideWindowCount
	c.ReplayMu.Unlock()
	if pre != 0 {
		t.Fatalf("OutsideWindowCount=%d before any outside-window event; want 0", pre)
	}

	// Now deliver the stale frame.
	if r := envelope.DecryptFrame(s.peerStore, stale[4:]); !errors.Is(r.Err, envelope.ErrOutsideWindow) {
		t.Fatalf("stale decrypt err=%v; want ErrOutsideWindow", r.Err)
	}
	c.ReplayMu.Lock()
	post := c.OutsideWindowCount
	c.ReplayMu.Unlock()
	if post != 1 {
		t.Fatalf("OutsideWindowCount=%d after one outside-window event; want 1", post)
	}

	// Successful decrypt resets to 0.
	f, _ := envelope.EncryptFrame(s.localStore, s.peerID, []byte("fresh"))
	if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
		t.Fatalf("fresh decrypt: %v", r.Err)
	}
	c.ReplayMu.Lock()
	post2 := c.OutsideWindowCount
	c.ReplayMu.Unlock()
	if post2 != 0 {
		t.Fatalf("OutsideWindowCount=%d after successful decrypt; want 0", post2)
	}
}

// TestShouldDropOnOutsideWindowGatesOnThresholdAndGrace pins the
// recovery trigger: the gate must require BOTH the count threshold
// AND the grace age to elapse. This is what the L7 handler uses to
// decide whether to drop crypto and request a rekey.
func TestShouldDropOnOutsideWindowGatesOnThresholdAndGrace(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	c := s.peerStore.Get(s.localID)
	if c == nil {
		t.Fatalf("no Crypto for local on peer side")
	}

	// Below threshold: never drop, regardless of age.
	c.ReplayMu.Lock()
	c.OutsideWindowCount = keyexchange.OutsideWindowDropThreshold - 1
	c.ReplayMu.Unlock()
	// Force age past grace so the only failing check is the threshold.
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.OutsideWindowDropGrace))
	if s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatalf("dropped at count<threshold")
	}

	// At threshold but within grace: don't drop yet.
	c.ReplayMu.Lock()
	c.OutsideWindowCount = keyexchange.OutsideWindowDropThreshold
	c.ReplayMu.Unlock()
	backdateCreatedAt(c, time.Now()) // fresh
	if s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatalf("dropped within grace period")
	}

	// Threshold met AND grace elapsed: drop.
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.OutsideWindowDropGrace))
	if !s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatalf("did not drop at threshold + past grace")
	}
}

// TestOutsideWindowDropEndToEnd is the smoking-gun reproduction of the
// list-agents bug: simulate 30+ consecutive outside-window rejections
// over the grace period, then assert the gate signals drop. Prior to
// the fix the count never moved (no recovery path); now it climbs and
// the gate trips, letting the L7 handler tear down the diverged Crypto.
func TestOutsideWindowDropEndToEnd(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// Capture N+1 stale frames before advancing peer's MaxRecvNonce so
	// that each one lands outside the window when delivered later.
	const stales = keyexchange.OutsideWindowDropThreshold + 1
	staleFrames := make([][]byte, stales)
	for i := 0; i < stales; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("stale"))
		if err != nil {
			t.Fatalf("encrypt stale #%d: %v", i, err)
		}
		staleFrames[i] = f
	}

	// Advance peer's window past all stale counters.
	advance := keyexchange.ReplayWindowSize + stales + 8
	for i := 0; i < advance; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("advance"))
		if err != nil {
			t.Fatalf("encrypt advance #%d: %v", i, err)
		}
		if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
			t.Fatalf("advance decrypt #%d: %v", i, r.Err)
		}
	}

	// Backdate Crypto so the grace gate is satisfied at the moment we
	// hit the count threshold below.
	c := s.peerStore.Get(s.localID)
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.OutsideWindowDropGrace))

	// Deliver the stale frames. Each one should produce ErrOutsideWindow
	// and bump the counter. ShouldDropOnOutsideWindow should flip true
	// once threshold is reached.
	for i, f := range staleFrames {
		r := envelope.DecryptFrame(s.peerStore, f[4:])
		if !errors.Is(r.Err, envelope.ErrOutsideWindow) {
			t.Fatalf("stale #%d err=%v; want ErrOutsideWindow", i, r.Err)
		}
	}

	if !s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		c.ReplayMu.Lock()
		count := c.OutsideWindowCount
		c.ReplayMu.Unlock()
		t.Fatalf("BUG-2: ShouldDropOnOutsideWindow=false after %d "+
			"consecutive ErrOutsideWindow (count=%d, threshold=%d)",
			stales, count, keyexchange.OutsideWindowDropThreshold)
	}
}

// backdateCreatedAt rewrites the CreatedAt timestamp on a Crypto so
// age-gated tests don't have to sleep through the real grace period.
func backdateCreatedAt(c *keyexchange.Crypto, when time.Time) {
	c.CreatedAt = when
}
