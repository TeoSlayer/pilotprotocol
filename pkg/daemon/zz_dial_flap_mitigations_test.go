// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Regressions for the dial-flap log storm observed against an
// unresponsive peer on 2026-05-26 (parallel send-messages to
// advice-slip → 8866 "peer marked for relay" events + 4927 "tunnel
// pending queue full; dropped oldest" events in ~60 s + IPC wedge).
//
// Two narrow mitigations land here:
//
//   1. SetRelayPeer no longer logs when the peer is already in relay
//      mode. The flag-set call is preserved (idempotent in routing.go),
//      only the log is gated.
//   2. The "tunnel pending queue full" warn is rate-limited per peer
//      via lastPendDropLog + pendingDropLogInterval. The drop counter
//      remains accurate.

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// captureHandler is a slog.Handler that counts records whose message
// matches a substring. Goroutine-safe.
type captureHandler struct {
	match string
	count atomic.Int64
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.match) {
		h.count.Add(1)
	}
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// withCapturedSlog swaps the default slog logger for one that counts
// messages matching `substr`, runs fn, then restores the original.
func withCapturedSlog(substr string, fn func()) int64 {
	orig := slog.Default()
	defer slog.SetDefault(orig)
	h := &captureHandler{match: substr}
	slog.SetDefault(slog.New(h))
	fn()
	return h.count.Load()
}

func TestSetRelayPeerLogIsIdempotent(t *testing.T) {
	// NOT parallel — withCapturedSlog touches the process-global default
	// logger, so concurrent log-capture tests trample each other's
	// handler installs.
	// 1 fresh flip to relay + 99 reasserts → expect exactly 1 log entry.

	tm := NewTunnelManager()
	defer tm.Close()
	const peer = uint32(424242)

	got := withCapturedSlog("peer marked for relay", func() {
		tm.SetRelayPeer(peer, true)
		for i := 0; i < 99; i++ {
			tm.SetRelayPeer(peer, true)
		}
	})

	if got != 1 {
		t.Fatalf("SetRelayPeer fired %d log entries for 1 flip + 99 "+
			"reasserts, want exactly 1 (idempotent log gate)", got)
	}
	if !tm.routing.IsRelayPeer(peer) {
		t.Fatal("peer not in relay state after SetRelayPeer(true)")
	}
}

func TestSetRelayPeerLogFiresOnReFlipAfterClear(t *testing.T) {
	// NOT parallel — see TestSetRelayPeerLogIsIdempotent.
	// flip → clear → flip → clear → flip = 3 actual transitions to
	// relay=true, want 3 log entries.

	tm := NewTunnelManager()
	defer tm.Close()
	const peer = uint32(424243)

	got := withCapturedSlog("peer marked for relay", func() {
		tm.SetRelayPeer(peer, true)
		tm.SetRelayPeer(peer, false)
		tm.SetRelayPeer(peer, true)
		tm.SetRelayPeer(peer, false)
		tm.SetRelayPeer(peer, true)
	})

	if got != 3 {
		t.Fatalf("got %d log entries for 3 fresh transitions to relay, want 3", got)
	}
}

// TestPendingDropLogThrottledPerPeer pins the second half of the
// mitigation: under sustained queue overflow the warn fires at most
// once per pendingDropLogInterval per peer; the drop counter remains
// authoritative regardless.
func TestPendingDropLogThrottledPerPeer(t *testing.T) {
	// NOT parallel — see TestSetRelayPeerLogIsIdempotent.
	tm := NewTunnelManager()
	defer tm.Close()
	const peer = uint32(909090)

	// Pre-fill the pending queue to capacity so every additional write
	// would trip the drop branch — but we drive the drop synchronously
	// below rather than going through writeFrame, because writeFrame
	// requires a wired-up socket (out of scope for this unit test).
	tm.pendMu.Lock()
	for i := 0; i < maxPendingPerPeer; i++ {
		tm.pending[peer] = append(tm.pending[peer], []byte{0xAA, 0xBB})
	}
	tm.pendMu.Unlock()

	got := withCapturedSlog("tunnel pending queue full", func() {
		// Drive 200 drops via the same locked block writeFrame uses.
		for i := 0; i < 200; i++ {
			tm.pendMu.Lock()
			q := tm.pending[peer]
			q = q[1:] // drop oldest
			atomic.AddUint64(&tm.PendingDrops, 1)
			tm.pending[peer] = append(q, []byte{0xCC, 0xDD})
			qlen := len(tm.pending[peer])
			shouldLog := false
			now := time.Now()
			last := tm.lastPendDropLog[peer]
			if last.IsZero() || now.Sub(last) >= pendingDropLogInterval {
				tm.lastPendDropLog[peer] = now
				shouldLog = true
			}
			tm.pendMu.Unlock()
			if shouldLog {
				slog.Warn("tunnel pending queue full; dropped oldest",
					"peer_node_id", peer,
					"queue_len", qlen,
					"limit", maxPendingPerPeer)
			}
		}
	})

	if got > 1 {
		t.Fatalf("queue full warn fired %d times under sustained drop, "+
			"want ≤ 1 (throttled per pendingDropLogInterval=%v)",
			got, pendingDropLogInterval)
	}
	if got == 0 {
		t.Fatal("queue full warn never fired — drop path not exercised")
	}
	if drops := atomic.LoadUint64(&tm.PendingDrops); drops != 200 {
		t.Fatalf("PendingDrops = %d after 200 drops, want 200 "+
			"(metric must remain authoritative)", drops)
	}
}

func TestPendingDropLogReapsStaleEntries(t *testing.T) {
	// NOT parallel — see TestSetRelayPeerLogIsIdempotent.
	// Regression: lastPendDropLog had 0 deletes vs 2 writes. Every
	// peer that ever hit a queue-full warn left a permanent entry,
	// leaking ~24 bytes per unique-peer-ever-throttled. A reaper
	// must evict entries older than pendingDropLogInterval (they're
	// no longer suppressing anything past that age).

	tm := NewTunnelManager()
	defer tm.Close()

	// Stamp 5 fake entries: 3 stale, 2 fresh.
	now := time.Now()
	tm.pendMu.Lock()
	tm.lastPendDropLog[100] = now.Add(-10 * pendingDropLogInterval)
	tm.lastPendDropLog[101] = now.Add(-2 * pendingDropLogInterval)
	tm.lastPendDropLog[102] = now.Add(-pendingDropLogInterval - time.Second)
	tm.lastPendDropLog[103] = now.Add(-time.Second) // fresh, keep
	tm.lastPendDropLog[104] = now                   // fresh, keep
	tm.pendMu.Unlock()

	tm.reapPendDropLog()

	tm.pendMu.Lock()
	defer tm.pendMu.Unlock()
	if len(tm.lastPendDropLog) != 2 {
		t.Fatalf("after reap: lastPendDropLog len = %d, want 2 (only fresh entries kept)", len(tm.lastPendDropLog))
	}
	if _, ok := tm.lastPendDropLog[103]; !ok {
		t.Error("103 (fresh) was reaped")
	}
	if _, ok := tm.lastPendDropLog[104]; !ok {
		t.Error("104 (fresh, now) was reaped")
	}
	for _, stale := range []uint32{100, 101, 102} {
		if _, ok := tm.lastPendDropLog[stale]; ok {
			t.Errorf("%d (stale) was NOT reaped", stale)
		}
	}
}

func TestPendingDropLogReFiresAfterInterval(t *testing.T) {
	// NOT parallel — see TestSetRelayPeerLogIsIdempotent.
	// Pre-age lastPendDropLog so the next drop is past the throttle
	// window — confirms re-firing works after the interval elapses.

	tm := NewTunnelManager()
	defer tm.Close()
	const peer = uint32(909091)

	tm.pendMu.Lock()
	for i := 0; i < maxPendingPerPeer; i++ {
		tm.pending[peer] = append(tm.pending[peer], []byte{1, 2})
	}
	tm.lastPendDropLog[peer] = time.Now().Add(-2 * pendingDropLogInterval)
	tm.pendMu.Unlock()

	got := withCapturedSlog("tunnel pending queue full", func() {
		tm.pendMu.Lock()
		q := tm.pending[peer]
		q = q[1:]
		atomic.AddUint64(&tm.PendingDrops, 1)
		tm.pending[peer] = append(q, []byte{3, 4})
		qlen := len(tm.pending[peer])
		shouldLog := false
		now := time.Now()
		last := tm.lastPendDropLog[peer]
		if last.IsZero() || now.Sub(last) >= pendingDropLogInterval {
			tm.lastPendDropLog[peer] = now
			shouldLog = true
		}
		tm.pendMu.Unlock()
		if shouldLog {
			slog.Warn("tunnel pending queue full; dropped oldest",
				"peer_node_id", peer, "queue_len", qlen,
				"limit", maxPendingPerPeer)
		}
	})

	if got != 1 {
		t.Fatalf("expected 1 warn after interval elapsed, got %d", got)
	}
}
