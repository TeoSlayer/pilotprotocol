// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"bytes"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestDaemonRoundtripHandshakeAndSendMessage (PILOT-163) is the smoke
// regression gate that every PR runs in the standard test step. It
// proves the protocol's happy path — handshake establishment, mutual
// trust, then a port listen + dial + write + accept + read — wires
// together end-to-end at every commit.
//
// Prior CI smoke only probed /api/stats and counted pod readiness;
// it would have green-lighted a build whose protocol layer was
// silently broken. This test runs in <500 ms in regular CI (no
// nightly build tag) so the cost of catching such breakage early is
// negligible.
//
// What's covered:
//   - Daemon boot (env.AddDaemon × 2 with encryption on)
//   - drv.Handshake() round-trip and PendingHandshakes/TrustedPeers
//     reaching mutual-trust state
//   - drv.Listen() port-binding via the driver socket
//   - drv.DialAddr() + Conn.Write() over the encrypted tunnel
//   - Listener.Accept() + Conn.Read() recovering the same payload bytes
//
// What's NOT covered (deliberate): NAT traversal (loopback only),
// long-running rekey, registry failover, plugin shutdown. Those have
// dedicated tests; this one is the smoke gate.
func TestDaemonRoundtripHandshakeAndSendMessage(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()

	env := NewTestEnv(t)
	a := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
	})
	b := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
	})

	t.Logf("daemon A: node=%d  addr=%s", a.Daemon.NodeID(), a.Daemon.Addr())
	t.Logf("daemon B: node=%d  addr=%s", b.Daemon.NodeID(), b.Daemon.Addr())

	// Mutual handshake — both directions auto-approve as a pair.
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "PILOT-163 roundtrip"); err != nil {
		t.Fatalf("A handshake to B: %v", err)
	}
	// Wait for B to see A's request in pending before B initiates back —
	// avoids a race where B's request lands first and A then rejects on
	// the duplicate-request guard.
	if !waitFor(2*time.Second, func() bool {
		p, err := b.Driver.PendingHandshakes()
		if err != nil {
			return false
		}
		list, _ := p["pending"].([]interface{})
		return len(list) > 0
	}) {
		t.Fatal("A's handshake never reached B (pending list stayed empty)")
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "PILOT-163 roundtrip reply"); err != nil {
		t.Fatalf("B handshake to A: %v", err)
	}

	if !waitFor(3*time.Second, func() bool {
		ta, errA := a.Driver.TrustedPeers()
		tb, errB := b.Driver.TrustedPeers()
		if errA != nil || errB != nil {
			return false
		}
		la, _ := ta["trusted"].([]interface{})
		lb, _ := tb["trusted"].([]interface{})
		return len(la) > 0 && len(lb) > 0
	}) {
		t.Fatal("mutual trust state never reached within 3s")
	}

	// Listen on B, dial-and-write from A, read back on B.
	const port = uint16(7163)
	const payloadStr = "PILOT-163 roundtrip payload"
	ln, err := b.Driver.Listen(port)
	if err != nil {
		t.Fatalf("B listen on %d: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Accept in a goroutine so we don't block the dial.
	type recvResult struct {
		data []byte
		err  error
	}
	recv := make(chan recvResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recv <- recvResult{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		recv <- recvResult{data: buf[:n], err: err}
	}()

	conn, err := a.Driver.DialAddrTimeout(b.Daemon.Addr(), port, 2*time.Second)
	if err != nil {
		t.Fatalf("A dial B:%d: %v", port, err)
	}
	if _, err := conn.Write([]byte(payloadStr)); err != nil {
		_ = conn.Close()
		t.Fatalf("A write: %v", err)
	}
	_ = conn.Close()

	select {
	case r := <-recv:
		if r.err != nil {
			t.Fatalf("B read: %v", r.err)
		}
		if !bytes.Equal(r.data, []byte(payloadStr)) {
			t.Errorf("B got %q, want %q", string(r.data), payloadStr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("B never received the message")
	}
}

// waitFor polls cond every 25 ms until it returns true or the deadline
// elapses. Returns the final cond result.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
