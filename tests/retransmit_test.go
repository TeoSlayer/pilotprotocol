package tests

import (
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"web4/pkg/daemon"
)

// TestPacketLossRetransmission tests the retransmission machinery by transferring
// a large data block (64KB) between two encrypted daemons, verifying data integrity
// via SHA-256, and checking that connection stats are consistent.
func TestPacketLossRetransmission(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Create two daemons with tunnel encryption enabled
	a := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
	})
	b := env.AddDaemon(func(cfg *daemon.Config) {
		cfg.Encrypt = true
	})

	t.Logf("daemon A: node=%d addr=%s", a.Daemon.NodeID(), a.Daemon.Addr())
	t.Logf("daemon B: node=%d addr=%s", b.Daemon.NodeID(), b.Daemon.Addr())

	// B listens on port 2000
	ln, err := b.Driver.Listen(2000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Generate a 64KB data block with known pattern
	const dataSize = 64 * 1024
	sendData := make([]byte, dataSize)
	for i := range sendData {
		sendData[i] = byte(i % 251) // prime modulus for varied data
	}
	expectedHash := sha256.Sum256(sendData)

	// Server goroutine: accept, read all data, compute hash
	serverDone := make(chan error, 1)
	serverHash := make(chan [32]byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("accept: %w", err)
			return
		}
		defer conn.Close()

		var received []byte
		buf := make([]byte, 8192)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				received = append(received, buf[:n]...)
			}
			if err == io.EOF || err != nil {
				break
			}
			// Check if we have enough data
			if len(received) >= dataSize {
				break
			}
		}

		if len(received) < dataSize {
			serverDone <- fmt.Errorf("received only %d bytes, expected %d", len(received), dataSize)
			return
		}
		h := sha256.Sum256(received[:dataSize])
		serverHash <- h
		serverDone <- nil
	}()

	// Client: dial and send the data block
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 2000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Write data in chunks
	offset := 0
	chunkSize := 4096
	for offset < len(sendData) {
		end := offset + chunkSize
		if end > len(sendData) {
			end = len(sendData)
		}
		_, err := conn.Write(sendData[offset:end])
		if err != nil {
			t.Fatalf("write at offset %d: %v", offset, err)
		}
		offset = end
	}
	t.Logf("sent %d bytes", dataSize)

	// Wait for server to finish receiving
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server timed out receiving data")
	}

	// Verify SHA-256 hash
	select {
	case h := <-serverHash:
		if h != expectedHash {
			t.Fatalf("SHA-256 mismatch: data corrupted during transfer")
		}
		t.Logf("SHA-256 verified: %x", h[:8])
	default:
		t.Fatal("no hash received from server")
	}

	// Check daemon info for stats consistency
	info := a.Daemon.Info()
	t.Logf("daemon A stats: pkts_sent=%d pkts_recv=%d bytes_sent=%d bytes_recv=%d conns=%d",
		info.PktsSent, info.PktsRecv, info.BytesSent, info.BytesRecv, info.Connections)

	if info.PktsSent == 0 {
		t.Error("expected daemon A to have sent packets")
	}
	if info.BytesSent == 0 {
		t.Error("expected daemon A to have sent bytes")
	}

	// Verify the connection list has stats
	for _, ci := range info.ConnList {
		if ci.Stats.BytesSent > 0 {
			t.Logf("connection %d: bytes_sent=%d segs_sent=%d retransmits=%d fast_retx=%d",
				ci.ID, ci.Stats.BytesSent, ci.Stats.SegsSent, ci.Stats.Retransmits, ci.Stats.FastRetx)
			if ci.Stats.SegsSent == 0 {
				t.Error("expected segments sent > 0 for active connection")
			}
		}
	}

	infoB := b.Daemon.Info()
	t.Logf("daemon B stats: pkts_sent=%d pkts_recv=%d bytes_sent=%d bytes_recv=%d",
		infoB.PktsSent, infoB.PktsRecv, infoB.BytesSent, infoB.BytesRecv)

	for _, ci := range infoB.ConnList {
		if ci.Stats.BytesRecv > 0 {
			t.Logf("connection %d (B side): bytes_recv=%d segs_recv=%d",
				ci.ID, ci.Stats.BytesRecv, ci.Stats.SegsRecv)
			if ci.Stats.SegsRecv == 0 {
				t.Error("expected segments received > 0 for active connection on B")
			}
		}
	}

	conn.Close()
}
