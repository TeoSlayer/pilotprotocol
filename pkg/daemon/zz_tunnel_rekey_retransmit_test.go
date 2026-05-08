// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestMarkPendingRekeyInitial verifies the first markPendingRekey for a
// peer creates an entry with attempts=1 and equal first/last sentAt.
func TestMarkPendingRekeyInitial(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.markPendingRekey(7)

	st := tm.kx.PendingRekeyForTest(7)
	if st == nil {
		t.Fatal("pendingRekey[7] missing")
	}
	if st.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", st.Attempts)
	}
	if !st.FirstSentAt.Equal(st.LastSentAt) {
		t.Fatalf("FirstSentAt = %v, LastSentAt = %v, want equal on initial",
			st.FirstSentAt, st.LastSentAt)
	}
}

// TestMarkPendingRekeyBumpsAttempts verifies subsequent calls keep
// firstSentAt but bump lastSentAt + attempts.
func TestMarkPendingRekeyBumpsAttempts(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.markPendingRekey(7)
	first := tm.kx.PendingRekeyForTest(7).FirstSentAt

	time.Sleep(2 * time.Millisecond)
	tm.markPendingRekey(7)

	st := tm.kx.PendingRekeyForTest(7)
	if st.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", st.Attempts)
	}
	if !st.FirstSentAt.Equal(first) {
		t.Fatalf("FirstSentAt drifted: %v vs %v", st.FirstSentAt, first)
	}
	if !st.LastSentAt.After(first) {
		t.Fatalf("LastSentAt = %v, want after FirstSentAt %v", st.LastSentAt, first)
	}
}

// TestClearPendingRekeyRemovesEntry verifies clearPendingRekey deletes.
func TestClearPendingRekeyRemovesEntry(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.markPendingRekey(7)
	tm.clearPendingRekey(7)

	if tm.kx.PendingRekeyHas(7) {
		t.Fatal("pendingRekey[7] still present after clear")
	}
}

// TestInboundDecryptStaleNoEntryReturnsTrue covers the never-decrypted
// case — we should reply to a peer's key_exchange even if we technically
// have crypto for them, since we have no proof they have ours.
func TestInboundDecryptStaleNoEntryReturnsTrue(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if !tm.inboundDecryptStale(7) {
		t.Fatal("inboundDecryptStale = false for never-decrypted peer; want true")
	}
}

// TestInboundDecryptStaleFreshReturnsFalse covers the recently-decrypted
// case — peer demonstrably has our key, no need to re-reply.
func TestInboundDecryptStaleFreshReturnsFalse(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.recordInboundDecrypt(7)
	if tm.inboundDecryptStale(7) {
		t.Fatal("inboundDecryptStale = true right after recordInboundDecrypt; want false")
	}
}

// TestInboundDecryptStaleAged checks we flip back to true past the
// staleness threshold. Uses direct map insertion to avoid wall-clock dep.
func TestInboundDecryptStaleAged(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.kx.SetLastInboundDecryptForTest(7, time.Now().Add(-2*keyExchangeReplyStaleThreshold))

	if !tm.inboundDecryptStale(7) {
		t.Fatal("inboundDecryptStale = false past staleness threshold; want true")
	}
}

// TestRekeyRetransmitTickSkipsFreshEntries covers the early-return when
// lastSentAt is more recent than rekeyRetransmitInterval — we shouldn't
// retransmit too eagerly.
func TestRekeyRetransmitTickSkipsFreshEntries(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.markPendingRekey(7)
	pre := tm.kx.PendingRekeyAttempts(7)

	// Fire the tick — fresh entry, should be untouched.
	tm.rekeyRetransmitTick()

	if !tm.kx.PendingRekeyHas(7) {
		t.Fatal("pendingRekey[7] missing after tick")
	}
	if got := tm.kx.PendingRekeyAttempts(7); got != pre {
		t.Fatalf("attempts changed (fresh entry retransmitted): %d -> %d", pre, got)
	}
}

// TestRekeyRetransmitTickGivesUpAtCap verifies the loop deletes peers that
// have exhausted their retry budget.
func TestRekeyRetransmitTickGivesUpAtCap(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	// Inject a maxed-out, stale entry directly to avoid driving
	// sendKeyExchangeToNode (which would try to write a frame on a nil
	// conn).
	tm.kx.InjectPendingRekeyForTest(7, &pendingRekeyState{
		FirstSentAt: time.Now().Add(-1 * time.Hour),
		LastSentAt:  time.Now().Add(-2 * rekeyRetransmitInterval),
		Attempts:    maxRekeyAttempts + 1,
	})

	tm.rekeyRetransmitTick()

	if tm.kx.PendingRekeyHas(7) {
		t.Fatal("pendingRekey[7] still present after exceeding cap")
	}
}

// TestRekeyRetransmitTickEmptyMapIsNoop is a sanity check — no panic
// when there's nothing to do.
func TestRekeyRetransmitTickEmptyMapIsNoop(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.rekeyRetransmitTick()
	// no panic = pass
}
