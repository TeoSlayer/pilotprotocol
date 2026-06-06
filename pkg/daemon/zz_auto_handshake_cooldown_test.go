// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Pins the per-peer auto-handshake cooldown that gates the inline
// DialConnection spawn of HandshakeSendRequest for peers in the
// trustedagents allowlist.
//
// Motivation: handshakeInFlight collapses CONCURRENT auto-handshake
// callers to a single underlying SendRequest. It does not collapse
// SEQUENTIAL callers — when SendRequest returns fast (e.g. sendMessage
// hits ErrEphemeralExhausted in microseconds, or the registry-relay
// fallback completes), the in-flight slot is released immediately and
// the next DialConnection caller re-fires the goroutine, re-enters
// SendRequest, and emits another "direct handshake failed" log line.
// Without a cooldown this produces a 4k-log-line-per-second storm
// against an unreachable trusted-agent (observed: 1 GB of daemon log
// in under 4 h against blockchain-ticker / node 19418, 2026-06-06).
//
// shouldAutoHandshake records the spawn time per peer and rejects
// subsequent calls within autoHandshakeCooldown. These tests verify
// that contract end-to-end without spinning up the full plugin stack.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestShouldAutoHandshakeFirstCallFires verifies the first call for an
// unseen peer always returns true (no cooldown to wait through).
func TestShouldAutoHandshakeFirstCallFires(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	if !d.shouldAutoHandshake(7777) {
		t.Fatalf("first call for an unseen peer must return true")
	}
}

// TestShouldAutoHandshakeRepeatWithinCooldownSuppressed verifies that
// subsequent calls within autoHandshakeCooldown return false — the
// regression that motivated the gate (4k-per-sec dial-driven re-entry).
func TestShouldAutoHandshakeRepeatWithinCooldownSuppressed(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	const peer = uint32(8888)

	if !d.shouldAutoHandshake(peer) {
		t.Fatalf("first call must fire")
	}
	for i := 0; i < 1000; i++ {
		if d.shouldAutoHandshake(peer) {
			t.Fatalf("repeat call %d within cooldown returned true; cooldown gate failed", i)
		}
	}
}

// TestShouldAutoHandshakeDifferentPeersIndependent verifies the cooldown
// is keyed strictly by peer ID — a hot dial path against peer A must
// not silence auto-handshakes to unrelated peer B.
func TestShouldAutoHandshakeDifferentPeersIndependent(t *testing.T) {
	t.Parallel()
	d := &Daemon{}

	if !d.shouldAutoHandshake(1001) {
		t.Fatalf("peer 1001 first call must fire")
	}
	if d.shouldAutoHandshake(1001) {
		t.Fatalf("peer 1001 second call within cooldown must skip")
	}
	if !d.shouldAutoHandshake(1002) {
		t.Fatalf("peer 1002 first call must fire (independent of 1001)")
	}
	if !d.shouldAutoHandshake(1003) {
		t.Fatalf("peer 1003 first call must fire (independent of 1001/1002)")
	}
}

// TestShouldAutoHandshakeConcurrentRacersOneWinner verifies the
// CompareAndSwap path: N goroutines racing to fire for the same peer
// must yield exactly one true result, the rest false.
func TestShouldAutoHandshakeConcurrentRacersOneWinner(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	const peer = uint32(2024)
	const N = 64

	var trueCount atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			if d.shouldAutoHandshake(peer) {
				trueCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := trueCount.Load(); got != 1 {
		t.Fatalf("%d goroutines saw shouldAutoHandshake=true, want exactly 1 (CompareAndSwap should pick one winner)", got)
	}
}

// TestShouldAutoHandshakeFiresAgainAfterCooldown verifies the gate
// releases when the cooldown elapses — a peer that's persistently
// unreachable still gets a fresh attempt periodically (so trust can
// converge once the peer comes back).
//
// Rather than sleep for autoHandshakeCooldown (30s), we directly seed
// the map with an old timestamp to simulate cooldown expiry. This
// pins the behaviour without making the test sleep through the real
// cooldown.
func TestShouldAutoHandshakeFiresAgainAfterCooldown(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	const peer = uint32(3030)

	// Seed an attempt that's well past the cooldown window.
	d.autoHandshakeLastAttempt.Store(peer, time.Now().Add(-2*autoHandshakeCooldown))

	if !d.shouldAutoHandshake(peer) {
		t.Fatalf("call after cooldown elapsed must fire")
	}
	if d.shouldAutoHandshake(peer) {
		t.Fatalf("immediately-following call within new cooldown must be suppressed")
	}
}

// TestShouldAutoHandshakeStormSuppression simulates the regression
// directly: a dial-driven hot path slams shouldAutoHandshake N times
// at a single peer in a tight loop, and we assert the gate caps the
// fanout at exactly 1 (so the goroutine spawn rate is bounded, not
// the 4000/sec storm observed in the wild).
func TestShouldAutoHandshakeStormSuppression(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	const peer = uint32(19418) // the real-world repro peer (blockchain-ticker)
	const N = 50_000

	fires := 0
	for i := 0; i < N; i++ {
		if d.shouldAutoHandshake(peer) {
			fires++
		}
	}
	if fires != 1 {
		t.Fatalf("auto-handshake fired %d times in a %d-call tight loop, want exactly 1 — storm suppression failed", fires, N)
	}
}
