// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Regression for the same-session log spam observed against list-agents
// on 2026-05-29: a fresh daemon registers, completes the initial PILA
// exchange (1 install, 1 postInstall, 1 "encrypted tunnel established"
// at Info), then the peer keeps retransmitting the SAME PILA at ~8 s
// cadence while the relayed data plane drops our PILS replies. Every
// such retransmit lands past DuplicateHandshakeDebounce (250 ms), so
// the duplicate gate doesn't catch it, but it carries the same X25519
// ephemeral so hadCrypto=true && keyChanged=false — structurally no
// new install. Pre-fix the daemon logged "encrypted tunnel established"
// at Info every time (35 events per peer per 5 min in field observation).
//
// The fix demotes the log to Debug for the same-session case while
// preserving:
//
//   - the existing duplicate-within-debounce coalescing
//     (TestDuplicatePILACoalescedSuppressesLogAndHook)
//
//   - the past-debounce postInstall hook firing for endpoint refresh
//     (TestDuplicatePILAOutsideDebounceFiresHookAgain pins hook count = 2)
//
//   - the asymmetric-recovery reply on stale inbound
//     (TestDuplicatePILAStillRepliesForAsymmetricRecovery)

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// syncWriter serialises Writes from slog handlers so concurrent
// goroutines logging into the same bytes.Buffer don't race the writes.
type syncWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (s syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// captureSlog redirects slog.Default to a buffer at the given level
// and returns a buffer-content snapshot + a restore func. NOT safe to
// use with t.Parallel() — slog.Default is process-global and parallel
// tests racing SetDefault see each other's handlers.
func captureSlog(t *testing.T, level slog.Level) (snapshot func() string, restore func()) {
	t.Helper()
	var (
		buf bytes.Buffer
		mu  sync.Mutex
	)
	handler := slog.NewTextHandler(syncWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: level})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	return func() string {
			mu.Lock()
			defer mu.Unlock()
			return buf.String()
		}, func() {
			slog.SetDefault(prev)
		}
}

// TestSameSessionPILASuppressesInfoButFiresHookAndDebug pins the fix
// end-to-end:
//
//   - First PILA: Info "encrypted tunnel established", hook count = 1.
//
//   - Second same-key PILA past the debounce window:
//
//   - hook still fires (count = 2, pinned for endpoint refresh by
//     TestDuplicatePILAOutsideDebounceFiresHookAgain).
//
//   - NO second "encrypted tunnel established" at Info — that was the
//     spam pre-fix.
//
//   - Debug-level "same-session keepalive" present (diagnostic
//     remains available for operators tracing key-exchange flow).
//
// The two slog assertions share one capture buffer (and therefore one
// SetDefault call) because parallel-test races on slog.Default would
// otherwise tear the captured output. The test itself is NOT marked
// t.Parallel().
func TestSameSessionPILASuppressesInfoButFiresHookAndDebug(t *testing.T) {
	a := newPeer(t, 510)
	b := newPeer(t, 511)
	crossWireVerifyFuncs(a, b)
	a.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	var hookCount atomic.Int32
	a.mgr.SetPostInstallHook(func(keyexchange.PostInstallEvent) {
		hookCount.Add(1)
	})

	bFrame := b.mgr.BuildAuthFrame()
	if bFrame == nil {
		t.Fatalf("BuildAuthFrame returned nil")
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// Capture at Debug so both the Info "established" on the first
	// arrival and the Debug "same-session keepalive" on the second
	// arrival land in the same buffer.
	logSnap, restore := captureSlog(t, slog.LevelDebug)
	defer restore()

	// --- First PILA: full install path ---------------------------------

	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("first PILA rejected")
	}
	if got := hookCount.Load(); got != 1 {
		t.Fatalf("after first PILA: hook count = %d, want 1", got)
	}
	initialLog := logSnap()
	if !strings.Contains(initialLog, "encrypted tunnel established") {
		t.Fatalf("first PILA: expected Info log 'encrypted tunnel established', got:\n%s", initialLog)
	}
	initialEstablishedCount := strings.Count(initialLog, "encrypted tunnel established")
	if initialEstablishedCount != 1 {
		t.Fatalf("first PILA: expected exactly 1 'established' log line, got %d:\n%s",
			initialEstablishedCount, initialLog)
	}

	// --- Second PILA past debounce: keepalive, no spam -----------------

	time.Sleep(keyexchange.DuplicateHandshakeDebounce + 100*time.Millisecond)

	if !a.mgr.HandleAuthFrame(bFrame[4:], from, false) {
		t.Fatalf("same-session PILA rejected")
	}

	// Endpoint-refresh contract from TestDuplicatePILAOutsideDebounceFiresHookAgain.
	if got := hookCount.Load(); got != 2 {
		t.Fatalf("after same-session PILA: hook count = %d, want 2 (must still refresh endpoint)", got)
	}

	finalLog := logSnap()

	// The new behaviour: the Info "established" count stays at one
	// (no spam from the second arrival).
	finalEstablishedCount := strings.Count(finalLog, "encrypted tunnel established")
	if finalEstablishedCount != 1 {
		t.Fatalf("after same-session PILA: 'established' log count = %d, want 1 (no Info spam):\n%s",
			finalEstablishedCount, finalLog)
	}

	// The Debug diagnostic remains so operators can see the keepalive.
	if !strings.Contains(finalLog, "same-session keepalive") {
		t.Fatalf("after same-session PILA: expected Debug log 'same-session keepalive'; got:\n%s",
			finalLog)
	}
}
