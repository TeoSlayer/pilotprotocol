// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Pins per-peer in-flight dedup for HandshakeSendRequest. The motivating
// symptom: a burst of `pilotctl handshake <agent>` commands (e.g. 7
// parallel handshakes) each fired its own DialConnection on port 444,
// each holding one ephemeral port for up to ~7.75 s (DialMaxRetries ×
// backoff). Concurrent intent toward the same peer was NOT collapsed, so
// the dial-side fanout multiplied the port-pool pressure under load and
// produced the "ephemeral ports exhausted" storm observed in the baseline
// reproduction (2026-05-31).
//
// The fix: HandshakeSendRequest records nodeID in d.handshakeInFlight on
// entry and removes it on return. Concurrent callers for the same peer
// observe the entry and short-circuit with ErrHandshakeInFlight. The
// first caller's underlying SendRequest runs once; subsequent callers
// see the in-flight signal and do nothing — no second dial, no second
// ephemeral port held.
//
// These tests verify both halves of that contract.

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// dedupFakeHandshakeService counts how many times SendRequest is called and
// optionally blocks the call to widen the in-flight window for race
// testing.
type dedupFakeHandshakeService struct {
	calls    atomic.Int32
	blockFor time.Duration
}

func (f *dedupFakeHandshakeService) IsTrusted(uint32) bool { return false }
func (f *dedupFakeHandshakeService) TrustedPeers() []HandshakeTrustRecord {
	return nil
}
func (f *dedupFakeHandshakeService) PendingRequests() []HandshakePendingRecord {
	return nil
}
func (f *dedupFakeHandshakeService) PendingCount() int { return 0 }
func (f *dedupFakeHandshakeService) SendRequest(uint32, string) error {
	f.calls.Add(1)
	if f.blockFor > 0 {
		time.Sleep(f.blockFor)
	}
	return nil
}
func (f *dedupFakeHandshakeService) ApproveHandshake(uint32) error        { return nil }
func (f *dedupFakeHandshakeService) RejectHandshake(uint32, string) error { return nil }
func (f *dedupFakeHandshakeService) RevokeTrust(uint32) error             { return nil }
func (f *dedupFakeHandshakeService) WaitForTrust(uint32, time.Duration) bool {
	return false
}
func (f *dedupFakeHandshakeService) ProcessRelayedRequest(uint32, string) {}
func (f *dedupFakeHandshakeService) ProcessRelayedApproval(uint32)        {}
func (f *dedupFakeHandshakeService) ProcessRelayedRejection(uint32)       {}
func (f *dedupFakeHandshakeService) Stop()                                {}

// TestHandshakeInFlightDedupCollapsesBurst verifies that N concurrent
// callers for the same peer produce exactly one underlying SendRequest
// call. The fake SendRequest blocks long enough for all goroutines to
// pile up in HandshakeSendRequest and observe the in-flight entry.
func TestHandshakeInFlightDedupCollapsesBurst(t *testing.T) {
	t.Parallel()

	fake := &dedupFakeHandshakeService{blockFor: 50 * time.Millisecond}
	d := &Daemon{handshakes: fake}

	const peer = uint32(42)
	const N = 16

	var wg sync.WaitGroup
	var inFlightCount atomic.Int32
	var okCount atomic.Int32
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			err := d.HandshakeSendRequest(peer, "test")
			switch {
			case err == nil:
				okCount.Add(1)
			case errors.Is(err, ErrHandshakeInFlight):
				inFlightCount.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := fake.calls.Load(); got != 1 {
		t.Errorf("underlying SendRequest called %d times, want 1 — dedup did not collapse the burst", got)
	}
	if got := okCount.Load(); got != 1 {
		t.Errorf("ok-count = %d, want 1 (only the first caller should see a non-error result)", got)
	}
	if got := inFlightCount.Load(); got != int32(N-1) {
		t.Errorf("in-flight-count = %d, want %d (N-1 contenders should observe the in-flight entry)", got, N-1)
	}
}

// TestHandshakeInFlightSlotReleasedOnReturn verifies the per-peer slot
// is freed once the underlying call completes — a second handshake to
// the same peer fired AFTER the first returns must proceed normally,
// not be permanently locked out.
func TestHandshakeInFlightSlotReleasedOnReturn(t *testing.T) {
	t.Parallel()

	fake := &dedupFakeHandshakeService{}
	d := &Daemon{handshakes: fake}

	const peer = uint32(99)

	if err := d.HandshakeSendRequest(peer, ""); err != nil {
		t.Fatalf("first call returned err: %v", err)
	}
	if err := d.HandshakeSendRequest(peer, ""); err != nil {
		t.Fatalf("second call (after first returned) returned err: %v", err)
	}
	if got := fake.calls.Load(); got != 2 {
		t.Errorf("underlying SendRequest called %d times, want 2 — slot was not released between sequential calls", got)
	}
}

// TestHandshakeInFlightDifferentPeersIndependent verifies dedup is
// keyed strictly by peer ID — concurrent handshakes to DIFFERENT peers
// must each proceed independently.
func TestHandshakeInFlightDifferentPeersIndependent(t *testing.T) {
	t.Parallel()

	fake := &dedupFakeHandshakeService{blockFor: 30 * time.Millisecond}
	d := &Daemon{handshakes: fake}

	const N = 5
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		peer := uint32(1000 + i)
		go func() {
			defer wg.Done()
			if err := d.HandshakeSendRequest(peer, ""); err != nil {
				t.Errorf("peer %d: unexpected err %v", peer, err)
			}
		}()
	}
	wg.Wait()

	if got := fake.calls.Load(); got != N {
		t.Errorf("SendRequest called %d times, want %d (per-peer dedup must not collapse distinct peers)", got, N)
	}
}

// TestHandshakeSendRequestNoServiceErr keeps the nil-service guard
// behavior pinned — when the plugin isn't registered, we return the
// existing "service not registered" error, not ErrHandshakeInFlight.
func TestHandshakeSendRequestNoServiceErr(t *testing.T) {
	t.Parallel()

	d := &Daemon{}
	err := d.HandshakeSendRequest(1, "")
	if err == nil {
		t.Fatalf("expected error when handshakes service is nil")
	}
	if errors.Is(err, ErrHandshakeInFlight) {
		t.Fatalf("got ErrHandshakeInFlight from nil-service path, want generic 'not registered' error")
	}
}
