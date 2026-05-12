// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

// Regression tests for the in-window replay-collision stuck-state bug
// observed in v1.10.0-rc5 against pilot-service-agents on 2026-05-11:
//
// After rolling rc5 out to ~436 agents on the production VM, the seven
// agents we had session state with *before* the rollout became
// permanently unreachable from this client. Symptom on the client:
// every dial timed out. Symptom in the daemon log: a steady stream of
// `tunnel nonce replay detected` warnings against those peers (and
// many more — the visible 7 were just the subset we pinged in the
// verification sweep).
//
// Root cause: each agent's daemon restarted with its persisted X25519
// identity intact. No PILA was negotiated. Their send counter reset
// to 1 while our MaxRecvNonce stayed at the pre-restart watermark
// (~50). The Mac side authenticated every subsequent frame against
// the same key but rejected it as a replay before AEAD-Open ever ran,
// because counter=1..50 had already been marked in the bitmap.
// DecryptFailCount and OutsideWindowCount never incremented — they
// only see post-AEAD or far-behind cases — so the existing rc5 recovery
// gates didn't engage. The wedge persisted indefinitely.
//
// The fix tracks consecutive in-window replay rejections on the
// Crypto (mirroring OutsideWindowCount) and surfaces a
// ShouldDropOnReplay gate that the L7 handler uses to drop + rekey.
// These tests exercise the keyexchange/envelope half of the fix;
// the tunnel.go wiring is covered by integration tests on the daemon.

import (
	"errors"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/envelope"
	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/keyexchange"
)

// TestReplayCountIncrementsAndResets pins the bookkeeping: each
// ErrReplay bumps ReplayCount; a successful decrypt resets it to 0.
// This is the input ShouldDropOnReplay consumes.
func TestReplayCountIncrementsAndResets(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// Encrypt one frame and deliver it cleanly to set the bit.
	f1, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("first"))
	if err != nil {
		t.Fatalf("encrypt first: %v", err)
	}
	if r := envelope.DecryptFrame(s.peerStore, f1[4:]); r.Err != nil {
		t.Fatalf("first decrypt: %v", r.Err)
	}

	c := s.peerStore.Get(s.localID)
	c.ReplayMu.Lock()
	pre := c.ReplayCount
	c.ReplayMu.Unlock()
	if pre != 0 {
		t.Fatalf("ReplayCount=%d before any replay event; want 0", pre)
	}

	// Re-deliver the same frame — same nonce, bit is already set,
	// in-window → ErrReplay.
	if r := envelope.DecryptFrame(s.peerStore, f1[4:]); !errors.Is(r.Err, envelope.ErrReplay) {
		t.Fatalf("replay decrypt err=%v; want ErrReplay", r.Err)
	}
	c.ReplayMu.Lock()
	post := c.ReplayCount
	c.ReplayMu.Unlock()
	if post != 1 {
		t.Fatalf("ReplayCount=%d after one replay event; want 1", post)
	}

	// A successful decrypt of a fresh frame resets the counter to 0.
	f2, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("second"))
	if err != nil {
		t.Fatalf("encrypt second: %v", err)
	}
	if r := envelope.DecryptFrame(s.peerStore, f2[4:]); r.Err != nil {
		t.Fatalf("second decrypt: %v", r.Err)
	}
	c.ReplayMu.Lock()
	post2 := c.ReplayCount
	c.ReplayMu.Unlock()
	if post2 != 0 {
		t.Fatalf("ReplayCount=%d after successful decrypt; want 0", post2)
	}
}

// TestReplayCountIsolatedFromOutsideWindow pins that ReplayCount and
// OutsideWindowCount track distinct failure modes. An outside-window
// rejection must NOT bump ReplayCount, and an in-window replay must
// NOT bump OutsideWindowCount — otherwise the gates would trip on
// each other's traffic.
func TestReplayCountIsolatedFromOutsideWindow(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// Stash a frame at counter=1, then advance peer's window past it.
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

	// Delivering the stale frame produces ErrOutsideWindow — verify
	// ReplayCount stays at 0.
	if r := envelope.DecryptFrame(s.peerStore, stale[4:]); !errors.Is(r.Err, envelope.ErrOutsideWindow) {
		t.Fatalf("stale decrypt err=%v; want ErrOutsideWindow", r.Err)
	}
	c := s.peerStore.Get(s.localID)
	c.ReplayMu.Lock()
	rc := c.ReplayCount
	owc := c.OutsideWindowCount
	c.ReplayMu.Unlock()
	if rc != 0 {
		t.Fatalf("ReplayCount=%d after ErrOutsideWindow; want 0 (counters must not cross-pollinate)", rc)
	}
	if owc != 1 {
		t.Fatalf("OutsideWindowCount=%d after one ErrOutsideWindow; want 1", owc)
	}
}

// TestShouldDropOnReplayGatesOnThresholdAndGrace pins the recovery
// trigger: the gate must require BOTH the count threshold AND the
// grace age. This is what the L7 handler uses to decide whether to
// drop crypto and request a rekey.
func TestShouldDropOnReplayGatesOnThresholdAndGrace(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	c := s.peerStore.Get(s.localID)
	if c == nil {
		t.Fatalf("no Crypto for local on peer side")
	}

	// Below threshold: never drop, regardless of age.
	c.ReplayMu.Lock()
	c.ReplayCount = keyexchange.ReplayDropThreshold - 1
	c.ReplayMu.Unlock()
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.ReplayDropGrace))
	if s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatalf("dropped at count<threshold")
	}

	// At threshold but within grace: don't drop yet.
	c.ReplayMu.Lock()
	c.ReplayCount = keyexchange.ReplayDropThreshold
	c.ReplayMu.Unlock()
	backdateCreatedAt(c, time.Now())
	if s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatalf("dropped within grace period")
	}

	// Threshold met AND grace elapsed: drop.
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.ReplayDropGrace))
	if !s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatalf("did not drop at threshold + past grace")
	}
}

// TestReplayDropEndToEnd is the smoking-gun reproduction of the
// rc5 list-agents wedge: simulate the peer-restart counter-reset
// scenario by accepting N frames, then re-delivering them. Each
// re-delivery is an in-window replay collision. Prior to the fix
// ReplayCount never moved (no recovery path). With the fix it climbs
// and ShouldDropOnReplay trips, letting the L7 handler tear down the
// wedged Crypto.
func TestReplayDropEndToEnd(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	// Build and deliver N frames so the bitmap has N consecutive bits
	// set and MaxRecvNonce sits at N. Mirrors the pre-restart state of
	// the wedged peers: counters 1..N had all been received cleanly.
	const frames = keyexchange.ReplayDropThreshold + 1
	delivered := make([][]byte, frames)
	for i := 0; i < frames; i++ {
		f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte("pre-restart"))
		if err != nil {
			t.Fatalf("encrypt pre-restart #%d: %v", i, err)
		}
		delivered[i] = f
		if r := envelope.DecryptFrame(s.peerStore, f[4:]); r.Err != nil {
			t.Fatalf("pre-restart decrypt #%d: %v", i, r.Err)
		}
	}

	// Backdate the Crypto so the grace gate is satisfied the instant
	// we cross the count threshold below.
	c := s.peerStore.Get(s.localID)
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.ReplayDropGrace))

	// Re-deliver every frame — the post-restart peer with counter
	// reset to 1 emits the same (counter, key) tuples we already
	// recorded. Each lands as ErrReplay.
	for i, f := range delivered {
		r := envelope.DecryptFrame(s.peerStore, f[4:])
		if !errors.Is(r.Err, envelope.ErrReplay) {
			t.Fatalf("replay #%d err=%v; want ErrReplay", i, r.Err)
		}
	}

	if !s.peerStore.ShouldDropOnReplay(s.localID, c) {
		c.ReplayMu.Lock()
		count := c.ReplayCount
		c.ReplayMu.Unlock()
		t.Fatalf("ShouldDropOnReplay=false after %d consecutive ErrReplay (count=%d, threshold=%d)",
			frames, count, keyexchange.ReplayDropThreshold)
	}
}

// TestReplayDropDoesNotStormAfterRekey pins the storm-safety guarantee
// against the historical v1.9.1 failure mode: each rekey installs a
// fresh Crypto whose early counters (1..40) can legitimately re-arrive
// via the relay path as ErrReplay; without grace protection those
// replays would re-trigger the drop+rekey, looping indefinitely.
//
// The rc6 fix relies on three guards working together to break the
// loop: threshold (need 30 replays), grace (3s minimum Crypto age),
// CompareAndDrop (only drops the exact instance whose count crossed
// threshold). This test exercises the grace guard: after the wedged
// session drops, the freshly installed Crypto receives a full burst
// of replays inside its grace window — ShouldDropOnReplay must stay
// false even with ReplayCount at threshold, preventing the storm.
func TestReplayDropDoesNotStormAfterRekey(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)

	c := s.peerStore.Get(s.localID)
	if c == nil {
		t.Fatalf("no Crypto for local on peer side")
	}

	// Simulate a fresh post-rekey Crypto: CreatedAt = now (grace
	// window still active). Pile ReplayCount to the threshold —
	// this models the worst case where the relay re-delivers every
	// frame in the fresh session as a duplicate.
	c.ReplayMu.Lock()
	c.ReplayCount = keyexchange.ReplayDropThreshold + 10
	c.ReplayMu.Unlock()
	backdateCreatedAt(c, time.Now())

	if s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatalf("v1.9.1 storm regression: drop fired inside grace window "+
			"(ReplayCount=%d, age<%v) — would loop rekey→fresh→replay→rekey",
			keyexchange.ReplayDropThreshold+10, keyexchange.ReplayDropGrace)
	}

	// After grace elapses, with the count still over threshold, the
	// gate MUST trip. This confirms grace is a *delay*, not a permanent
	// disable: a session that genuinely stays wedged past the grace
	// window does get torn down.
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.ReplayDropGrace))
	if !s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatalf("gate did not trip after grace elapsed at count>=threshold")
	}
}
