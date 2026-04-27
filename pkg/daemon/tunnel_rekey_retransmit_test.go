// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestMarkPendingRekeyInitial verifies the first markPendingRekey for a
// peer creates an entry with attempts=1 and equal first/last sentAt.
func TestMarkPendingRekeyInitial(t *testing.T) {
	tm := NewTunnelManager()
	tm.markPendingRekey(7)

	tm.rkPendingMu.Lock()
	defer tm.rkPendingMu.Unlock()
	st, ok := tm.pendingRekey[7]
	if !ok {
		t.Fatal("pendingRekey[7] missing")
	}
	if st.attempts != 1 {
		t.Fatalf("attempts = %d, want 1", st.attempts)
	}
	if !st.firstSentAt.Equal(st.lastSentAt) {
		t.Fatalf("firstSentAt = %v, lastSentAt = %v, want equal on initial",
			st.firstSentAt, st.lastSentAt)
	}
}

// TestMarkPendingRekeyBumpsAttempts verifies subsequent calls keep
// firstSentAt but bump lastSentAt + attempts.
func TestMarkPendingRekeyBumpsAttempts(t *testing.T) {
	tm := NewTunnelManager()
	tm.markPendingRekey(7)
	first := tm.pendingRekey[7].firstSentAt

	time.Sleep(2 * time.Millisecond)
	tm.markPendingRekey(7)

	st := tm.pendingRekey[7]
	if st.attempts != 2 {
		t.Fatalf("attempts = %d, want 2", st.attempts)
	}
	if !st.firstSentAt.Equal(first) {
		t.Fatalf("firstSentAt drifted: %v vs %v", st.firstSentAt, first)
	}
	if !st.lastSentAt.After(first) {
		t.Fatalf("lastSentAt = %v, want after firstSentAt %v", st.lastSentAt, first)
	}
}

// TestClearPendingRekeyRemovesEntry verifies clearPendingRekey deletes.
func TestClearPendingRekeyRemovesEntry(t *testing.T) {
	tm := NewTunnelManager()
	tm.markPendingRekey(7)
	tm.clearPendingRekey(7)

	tm.rkPendingMu.Lock()
	defer tm.rkPendingMu.Unlock()
	if _, ok := tm.pendingRekey[7]; ok {
		t.Fatal("pendingRekey[7] still present after clear")
	}
}

// TestInboundDecryptStaleNoEntryReturnsTrue covers the never-decrypted
// case — we should reply to a peer's key_exchange even if we technically
// have crypto for them, since we have no proof they have ours.
func TestInboundDecryptStaleNoEntryReturnsTrue(t *testing.T) {
	tm := NewTunnelManager()
	if !tm.inboundDecryptStale(7) {
		t.Fatal("inboundDecryptStale = false for never-decrypted peer; want true")
	}
}

// TestInboundDecryptStaleFreshReturnsFalse covers the recently-decrypted
// case — peer demonstrably has our key, no need to re-reply.
func TestInboundDecryptStaleFreshReturnsFalse(t *testing.T) {
	tm := NewTunnelManager()
	tm.recordInboundDecrypt(7)
	if tm.inboundDecryptStale(7) {
		t.Fatal("inboundDecryptStale = true right after recordInboundDecrypt; want false")
	}
}

// TestInboundDecryptStaleAged checks we flip back to true past the
// staleness threshold. Uses direct map insertion to avoid wall-clock dep.
func TestInboundDecryptStaleAged(t *testing.T) {
	tm := NewTunnelManager()
	tm.rkPendingMu.Lock()
	tm.lastInboundDecrypt[7] = time.Now().Add(-2 * keyExchangeReplyStaleThreshold)
	tm.rkPendingMu.Unlock()

	if !tm.inboundDecryptStale(7) {
		t.Fatal("inboundDecryptStale = false past staleness threshold; want true")
	}
}

// TestRekeyRetransmitTickSkipsFreshEntries covers the early-return when
// lastSentAt is more recent than rekeyRetransmitInterval — we shouldn't
// retransmit too eagerly.
func TestRekeyRetransmitTickSkipsFreshEntries(t *testing.T) {
	tm := NewTunnelManager()
	tm.markPendingRekey(7)
	pre := tm.pendingRekey[7].attempts

	// Fire the tick — fresh entry, should be untouched.
	tm.rekeyRetransmitTick()

	if tm.pendingRekey[7] == nil {
		t.Fatal("pendingRekey[7] missing after tick")
	}
	if got := tm.pendingRekey[7].attempts; got != pre {
		t.Fatalf("attempts changed (fresh entry retransmitted): %d -> %d", pre, got)
	}
}

// TestRekeyRetransmitTickGivesUpAtCap verifies the loop deletes peers that
// have exhausted their retry budget.
func TestRekeyRetransmitTickGivesUpAtCap(t *testing.T) {
	tm := NewTunnelManager()
	// Inject a maxed-out, stale entry directly to avoid driving
	// sendKeyExchangeToNode (which would try to write a frame on a nil
	// conn).
	tm.rkPendingMu.Lock()
	tm.pendingRekey[7] = &pendingRekeyState{
		firstSentAt: time.Now().Add(-1 * time.Hour),
		lastSentAt:  time.Now().Add(-2 * rekeyRetransmitInterval),
		attempts:    maxRekeyAttempts + 1,
	}
	tm.rkPendingMu.Unlock()

	tm.rekeyRetransmitTick()

	tm.rkPendingMu.Lock()
	defer tm.rkPendingMu.Unlock()
	if _, ok := tm.pendingRekey[7]; ok {
		t.Fatal("pendingRekey[7] still present after exceeding cap")
	}
}

// TestRekeyRetransmitTickEmptyMapIsNoop is a sanity check — no panic
// when there's nothing to do.
func TestRekeyRetransmitTickEmptyMapIsNoop(t *testing.T) {
	tm := NewTunnelManager()
	tm.rekeyRetransmitTick()
	// no panic = pass
}
