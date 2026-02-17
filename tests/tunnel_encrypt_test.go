package tests

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

func TestTunnelEncryption(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Start daemon A with encryption
	infoA := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	daemonA := infoA.Daemon
	drvA := infoA.Driver

	t.Logf("daemon A: node=%d addr=%s (encrypted)", daemonA.NodeID(), daemonA.Addr())

	// Start daemon B with encryption
	infoB := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	daemonB := infoB.Daemon
	drvB := infoB.Driver

	t.Logf("daemon B: node=%d addr=%s (encrypted)", daemonB.NodeID(), daemonB.Addr())

	// Listen on port 2000
	ln, err := drvA.Listen(2000)
	if err != nil {
		t.Fatalf("driver A listen: %v", err)
	}

	// Server: accept and echo
	serverDone := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Sprintf("accept error: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Sprintf("read error: %v", err)
			return
		}
		conn.Write(buf[:n])
		serverDone <- string(buf[:n])
	}()

	// Dial A from B
	conn, err := drvB.Dial(daemonA.Addr().String() + ":2000")
	if err != nil {
		t.Fatalf("driver B dial: %v", err)
	}
	defer conn.Close()

	// Send data through encrypted tunnel
	msg := "hello through encrypted tunnel"
	conn.Write([]byte(msg))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}

	echo := string(buf[:n])
	if echo != msg {
		t.Fatalf("echo mismatch: got %q, want %q", echo, msg)
	}

	t.Logf("encrypted echo: %q", echo)

	// Wait for server
	select {
	case result := <-serverDone:
		t.Logf("server received: %q", result)
	case <-time.After(5 * time.Second):
		t.Fatal("server timeout")
	}

	// Poll until both daemons report encrypted peers
	deadline := time.After(5 * time.Second)
	var infoAd, infoBd *daemon.DaemonInfo
	for {
		infoAd = daemonA.Info()
		infoBd = daemonB.Info()
		if infoAd.EncryptedPeers > 0 && infoBd.EncryptedPeers > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for encrypted peers: A=%d B=%d",
				infoAd.EncryptedPeers, infoBd.EncryptedPeers)
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Logf("daemon A: encrypt=%v, peers=%d, encrypted_peers=%d", infoAd.Encrypt, infoAd.Peers, infoAd.EncryptedPeers)
	t.Logf("daemon B: encrypt=%v, peers=%d, encrypted_peers=%d", infoBd.Encrypt, infoBd.Peers, infoBd.EncryptedPeers)

	if !infoAd.Encrypt {
		t.Error("daemon A: encryption not enabled")
	}
	if !infoBd.Encrypt {
		t.Error("daemon B: encryption not enabled")
	}
	if infoAd.EncryptedPeers == 0 {
		t.Error("daemon A: no encrypted peers")
	}
	if infoBd.EncryptedPeers == 0 {
		t.Error("daemon B: no encrypted peers")
	}

	// Verify peer list shows encryption
	for _, p := range infoAd.PeerList {
		t.Logf("  peer node %d: encrypted=%v", p.NodeID, p.Encrypted)
		if !p.Encrypted {
			t.Errorf("peer %d should be encrypted", p.NodeID)
		}
	}
}

func TestTunnelEncryptionBackwardCompat(t *testing.T) {
	t.Parallel()
	// Test that an encrypted daemon can talk to an unencrypted daemon
	// (falls back to plaintext)

	env := NewTestEnv(t)

	// Start daemon A with encryption
	infoA := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	daemonA := infoA.Daemon
	drvA := infoA.Driver

	// Start daemon B WITHOUT encryption
	infoB := env.AddDaemon()
	drvB := infoB.Driver

	t.Logf("daemon A: encrypted, daemon B: plaintext")

	ln, err := drvA.Listen(2001)
	if err != nil {
		t.Fatalf("driver A listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	conn, err := drvB.Dial(daemonA.Addr().String() + ":2001")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := "plaintext fallback test"
	conn.Write([]byte(msg))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), msg)
	}

	t.Logf("backward-compatible echo: %q", string(buf[:n]))
}

func TestAuthenticatedKeyExchange(t *testing.T) {
	t.Parallel()
	// Test that two daemons with identity + encryption establish authenticated tunnels
	env := NewTestEnv(t)

	identityDirA := t.TempDir()
	identityDirB := t.TempDir()

	// Start daemon A with encryption + identity
	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(identityDirA, "identity.json")
	})
	daemonA := infoA.Daemon
	drvA := infoA.Driver

	// Start daemon B with encryption + identity
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(identityDirB, "identity.json")
	})
	daemonB := infoB.Daemon
	drvB := infoB.Driver

	t.Logf("daemon A: node=%d, daemon B: node=%d (both encrypted + identity)", daemonA.NodeID(), daemonB.NodeID())

	// Connect and exchange data
	ln, err := drvA.Listen(2002)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverDone := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Sprintf("accept: %v", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverDone <- fmt.Sprintf("read: %v", err)
			return
		}
		conn.Write(buf[:n])
		serverDone <- string(buf[:n])
	}()

	conn, err := drvB.Dial(daemonA.Addr().String() + ":2002")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := "authenticated tunnel test"
	conn.Write([]byte(msg))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf[:n]), msg)
	}

	select {
	case result := <-serverDone:
		t.Logf("server received: %q", result)
	case <-time.After(5 * time.Second):
		t.Fatal("server timeout")
	}

	// Poll until both daemons report authenticated peers
	deadline := time.After(5 * time.Second)
	var infoAd, infoBd *daemon.DaemonInfo
	for {
		infoAd = daemonA.Info()
		infoBd = daemonB.Info()
		if infoAd.AuthenticatedPeers > 0 && infoBd.AuthenticatedPeers > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for authenticated peers: A=%d B=%d",
				infoAd.AuthenticatedPeers, infoBd.AuthenticatedPeers)
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Logf("daemon A: peers=%d, encrypted=%d, authenticated=%d",
		infoAd.Peers, infoAd.EncryptedPeers, infoAd.AuthenticatedPeers)
	t.Logf("daemon B: peers=%d, encrypted=%d, authenticated=%d",
		infoBd.Peers, infoBd.EncryptedPeers, infoBd.AuthenticatedPeers)

	if infoAd.EncryptedPeers == 0 {
		t.Error("daemon A: no encrypted peers")
	}
	if infoBd.EncryptedPeers == 0 {
		t.Error("daemon B: no encrypted peers")
	}
	if infoAd.AuthenticatedPeers == 0 {
		t.Error("daemon A: no authenticated peers")
	}
	if infoBd.AuthenticatedPeers == 0 {
		t.Error("daemon B: no authenticated peers")
	}

	for _, p := range infoAd.PeerList {
		t.Logf("  A -> peer %d: encrypted=%v authenticated=%v", p.NodeID, p.Encrypted, p.Authenticated)
	}
	for _, p := range infoBd.PeerList {
		t.Logf("  B -> peer %d: encrypted=%v authenticated=%v", p.NodeID, p.Encrypted, p.Authenticated)
	}
}

// TestEncryptedLargeTransfer sends a large payload through an encrypted tunnel.
func TestEncryptedLargeTransfer(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
		c.IdentityPath = filepath.Join(t.TempDir(), "identity.json")
	})

	drvA := infoA.Driver
	drvB := infoB.Driver

	ln, err := drvA.Listen(3000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Server: receive all data and send back the total length
	serverDone := make(chan int, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		total := 0
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		serverDone <- total
	}()

	conn, err := drvB.Dial(infoA.Daemon.Addr().String() + ":3000")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 256KB through encrypted tunnel
	payload := make([]byte, 256*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	written := 0
	for written < len(payload) {
		end := written + 4096
		if end > len(payload) {
			end = len(payload)
		}
		n, err := conn.Write(payload[written:end])
		if err != nil {
			t.Fatalf("write at offset %d: %v", written, err)
		}
		written += n
	}
	conn.Close()

	select {
	case total := <-serverDone:
		if total != len(payload) {
			t.Errorf("expected %d bytes, server received %d", len(payload), total)
		}
		t.Logf("encrypted transfer: %d bytes sent and received", total)
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for server to finish")
	}
}

// TestEncryptedBidirectional verifies encrypted bidirectional communication.
func TestEncryptedBidirectional(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
	})
	infoB := env.AddDaemon(func(c *daemon.Config) {
		c.Encrypt = true
	})

	drvA := infoA.Driver
	drvB := infoB.Driver

	ln, err := drvA.Listen(3001)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serverConn := make(chan io.ReadWriteCloser, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		serverConn <- conn
	}()

	clientConn, err := drvB.Dial(infoA.Daemon.Addr().String() + ":3001")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()

	select {
	case srvConn := <-serverConn:
		defer srvConn.Close()

		// Both sides write and read simultaneously
		var wg sync.WaitGroup
		errCh := make(chan error, 4)

		msgAtoB := bytes.Repeat([]byte("A"), 4096)
		msgBtoA := bytes.Repeat([]byte("B"), 4096)

		// A writes
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := srvConn.Write(msgAtoB); err != nil {
				errCh <- fmt.Errorf("A write: %w", err)
			}
		}()

		// B writes
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := clientConn.Write(msgBtoA); err != nil {
				errCh <- fmt.Errorf("B write: %w", err)
			}
		}()

		// A reads what B sent
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 8192)
			total := 0
			for total < len(msgBtoA) {
				n, err := srvConn.Read(buf[total:])
				if err != nil {
					errCh <- fmt.Errorf("A read: %w", err)
					return
				}
				total += n
			}
			if !bytes.Equal(buf[:total], msgBtoA) {
				errCh <- fmt.Errorf("A received corrupted data")
			}
		}()

		// B reads what A sent
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 8192)
			total := 0
			for total < len(msgAtoB) {
				n, err := clientConn.Read(buf[total:])
				if err != nil {
					errCh <- fmt.Errorf("B read: %w", err)
					return
				}
				total += n
			}
			if !bytes.Equal(buf[:total], msgAtoB) {
				errCh <- fmt.Errorf("B received corrupted data")
			}
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			t.Log("encrypted bidirectional transfer succeeded")
		case err := <-errCh:
			t.Fatal(err)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout")
		}

	case <-time.After(5 * time.Second):
		t.Fatal("accept timeout")
	}
}
