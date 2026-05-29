// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

// Tests for the IPC primitives that maybeAutoHandshake in cmd/pilotctl/main.go
// relies on. The function itself calls os.Exit so it cannot be unit-tested
// directly; these tests verify its three branches at the driver-API level.
//
// Branch 1 — already trusted: WaitForTrust(nodeID, 0) → trusted=true, fast.
// Branch 2 — trusted agent: Handshake + WaitForTrust(nodeID, 5000) resolves.
// Branch 3 — unknown peer: registry says public → allow; private → refuse.
//            Branch 3 public/private is enforced at the daemon level; see
//            TestPrivateDaemonRejectsUntrustedDial below.

import (
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// TestWaitForTrustSelf checks that a daemon always considers itself trusted.
// maybeAutoHandshake branch 1 relies on WaitForTrust(own_node, 0)→trusted.
func TestWaitForTrustSelf(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()

	resp, err := a.Driver.WaitForTrust(a.Daemon.NodeID(), 0)
	if err != nil {
		t.Fatalf("WaitForTrust(self, 0): %v", err)
	}
	trusted, _ := resp["trusted"].(bool)
	if !trusted {
		t.Errorf("WaitForTrust(self, 0) = false, want true (self is always trusted)")
	}
}

// TestWaitForTrustUnknownNodeReturnsImmediately checks that WaitForTrust with
// zero timeout returns false immediately for an untrusted peer. This is the
// non-blocking fast-path check that maybeAutoHandshake uses at the top of
// branch 1 to decide whether to skip the full handshake flow.
func TestWaitForTrustUnknownNodeReturnsImmediately(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	start := time.Now()
	resp, err := a.Driver.WaitForTrust(b.Daemon.NodeID(), 0)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForTrust(unknown, 0): %v", err)
	}
	trusted, _ := resp["trusted"].(bool)
	if trusted {
		t.Errorf("WaitForTrust(unknown, 0) = true, want false (no trust established)")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("WaitForTrust(unknown, 0) took %v, want <500ms (should not block)", elapsed)
	}
}

// TestWaitForTrustFastPathAfterTrust verifies that once trust is established,
// WaitForTrust(nodeID, 0) returns trusted=true on the fast path.
// This is exactly what maybeAutoHandshake branch 1 executes on second invocation.
func TestWaitForTrustFastPathAfterTrust(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	b := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })

	// Establish trust: A→B mutual handshake.
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "pre-trust"); err != nil {
		t.Fatalf("A handshake: %v", err)
	}

	// Wait for B to see the pending request.
	deadline := time.After(5 * time.Second)
	for {
		pend, err := b.Driver.PendingHandshakes()
		if err == nil {
			if pl, _ := pend["pending"].([]interface{}); len(pl) > 0 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timeout: B never received A's handshake request")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// B approves → both sides become trusted.
	if _, err := b.Driver.ApproveHandshake(a.Daemon.NodeID(), ""); err != nil {
		t.Fatalf("B approve: %v", err)
	}

	// Poll until A sees B as trusted.
	deadline = time.After(5 * time.Second)
	for {
		trust, err := a.Driver.TrustedPeers()
		if err == nil {
			if tl, _ := trust["trusted"].([]interface{}); len(tl) > 0 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timeout: A never saw B as trusted")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Now the fast-path check: WaitForTrust(B, 0) must return true immediately.
	start := time.Now()
	resp, err := a.Driver.WaitForTrust(b.Daemon.NodeID(), 0)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForTrust(trusted, 0): %v", err)
	}
	trusted, _ := resp["trusted"].(bool)
	if !trusted {
		t.Errorf("WaitForTrust(trusted, 0) = false, want true (trust already established)")
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("WaitForTrust(trusted, 0) took %v, want <200ms (should be fast path)", elapsed)
	}
}

// TestWaitForTrustBlocksUntilApproved mirrors maybeAutoHandshake branch 2:
// call Handshake then WaitForTrust(5000) concurrently while the remote approves.
// Trust should resolve well within the 5s window (typically <2s).
func TestWaitForTrustBlocksUntilApproved(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	b := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })

	// A sends handshake to B.
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "auto-handshake"); err != nil {
		t.Fatalf("A handshake: %v", err)
	}

	// Concurrently: A waits for trust (up to 5s); B approves after seeing the request.
	var wg sync.WaitGroup
	var waitResp map[string]interface{}
	var waitErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		waitResp, waitErr = a.Driver.WaitForTrust(b.Daemon.NodeID(), 5000)
	}()

	// B polls for A's request then approves.
	deadline := time.After(5 * time.Second)
	for {
		pend, err := b.Driver.PendingHandshakes()
		if err == nil {
			if pl, _ := pend["pending"].([]interface{}); len(pl) > 0 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timeout: B never received A's handshake request")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if _, err := b.Driver.ApproveHandshake(a.Daemon.NodeID(), ""); err != nil {
		t.Fatalf("B approve: %v", err)
	}

	// The concurrent WaitForTrust should wake promptly.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForTrust did not return within 5s after approval")
	}

	if waitErr != nil {
		t.Fatalf("WaitForTrust error: %v", waitErr)
	}
	trusted, _ := waitResp["trusted"].(bool)
	if !trusted {
		t.Errorf("WaitForTrust(5000) = false, want true (B approved before timeout)")
	}
}

// TestWaitForTrustTimeout checks that WaitForTrust returns trusted=false when
// the timeout elapses with no approval. Used to verify the 5s branch-2 path
// degrades gracefully (pilotctl continues rather than hanging forever).
func TestWaitForTrustTimeout(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Use a short timeout so the test stays fast.
	const timeoutMs = 100
	start := time.Now()
	resp, err := a.Driver.WaitForTrust(b.Daemon.NodeID(), timeoutMs)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("WaitForTrust(100ms): %v", err)
	}
	trusted, _ := resp["trusted"].(bool)
	if trusted {
		t.Errorf("WaitForTrust(100ms) = true, want false (no approval before timeout)")
	}
	if elapsed < 80*time.Millisecond {
		t.Errorf("WaitForTrust returned after only %v, want ≥80ms (should wait for timeout)", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Errorf("WaitForTrust took %v, want <2s (timeout should not block long)", elapsed)
	}
}

// TestPrivateDaemonRejectsUntrustedDial exercises maybeAutoHandshake branch 3
// at the daemon level. A private daemon silently drops SYNs from untrusted
// peers — pilotctl refuses upfront to give the user a clear error rather than
// a dial timeout. This test confirms the daemon-side enforcement that makes
// branch 3 necessary.
func TestPrivateDaemonRejectsUntrustedDial(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// B is a private daemon (no incoming connections from untrusted nodes).
	a := env.AddDaemon()
	b := env.AddDaemon(func(c *daemon.Config) {
		c.Public = false
	})

	// A tries to dial B without trust — should fail or time out quickly.
	ln, err := b.Driver.Listen(9900)
	if err != nil {
		t.Fatalf("B listen: %v", err)
	}
	defer ln.Close()

	conn, dialErr := a.Driver.DialAddrTimeout(b.Daemon.Addr(), 9900, 2*time.Second)
	if dialErr == nil {
		conn.Close()
		t.Error("expected dial to private untrusted daemon to fail, but it succeeded")
	}
	// Any error (timeout, refused, etc.) is acceptable — the key is that
	// an untrusted client cannot freely connect to a private daemon.
}
