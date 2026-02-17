package tests

import (
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
)

// TestSACKEncoding verifies SACK block encode/decode round-trip.
func TestSACKEncoding(t *testing.T) {
	t.Parallel()
	blocks := []daemon.SACKBlock{
		{Left: 4096, Right: 8192},
		{Left: 12288, Right: 16384},
		{Left: 20480, Right: 28672},
	}

	encoded := daemon.EncodeSACK(blocks)
	if encoded == nil {
		t.Fatal("EncodeSACK returned nil")
	}

	decoded, ok := daemon.DecodeSACK(encoded)
	if !ok {
		t.Fatal("DecodeSACK failed")
	}

	if len(decoded) != len(blocks) {
		t.Fatalf("expected %d blocks, got %d", len(blocks), len(decoded))
	}

	for i, b := range decoded {
		if b.Left != blocks[i].Left || b.Right != blocks[i].Right {
			t.Errorf("block %d: expected [%d,%d), got [%d,%d)", i, blocks[i].Left, blocks[i].Right, b.Left, b.Right)
		}
	}

	// Verify non-SACK data is not parsed as SACK
	_, ok = daemon.DecodeSACK([]byte("hello world"))
	if ok {
		t.Error("should not decode arbitrary data as SACK")
	}

	_, ok = daemon.DecodeSACK(nil)
	if ok {
		t.Error("should not decode nil as SACK")
	}

	t.Logf("SACK encoding round-trip: %d blocks, %d bytes", len(blocks), len(encoded))
}

// TestSACKTransfer verifies that large transfers with SACK enabled complete correctly.
// This test sends a 128KB payload through an echo server and verifies integrity.
func TestSACKTransfer(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Disable built-in echo so test can bind port 7 via driver
	disableEcho := func(cfg *daemon.Config) { cfg.DisableEcho = true }
	a := env.AddDaemon(disableEcho)
	b := env.AddDaemon(disableEcho)

	// Echo server on A
	ln, err := a.Driver.Listen(7)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 8192)
				for {
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Client on B
	conn, err := b.Driver.Dial(fmt.Sprintf("%s:7", a.Daemon.Addr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send 128KB of data
	totalSize := 128 * 1024
	sendData := make([]byte, totalSize)
	for i := range sendData {
		sendData[i] = byte(i % 251)
	}
	sendHash := sha256.Sum256(sendData)

	start := time.Now()

	// Send all data
	written := 0
	for written < totalSize {
		end := written + 8192
		if end > totalSize {
			end = totalSize
		}
		n, err := conn.Write(sendData[written:end])
		if err != nil {
			t.Fatalf("write at %d: %v", written, err)
		}
		written += n
	}

	// Read all echoed data
	recvData := make([]byte, 0, totalSize)
	buf := make([]byte, 8192)
	deadline := time.After(10 * time.Second)
	for len(recvData) < totalSize {
		select {
		case <-deadline:
			t.Fatalf("timeout: received %d/%d bytes", len(recvData), totalSize)
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (got %d/%d)", err, len(recvData), totalSize)
		}
		recvData = append(recvData, buf[:n]...)
	}

	elapsed := time.Since(start)
	recvHash := sha256.Sum256(recvData)

	if sendHash != recvHash {
		t.Fatalf("hash mismatch: sent %x, received %x", sendHash[:8], recvHash[:8])
	}

	speed := float64(totalSize*2) / elapsed.Seconds() / 1024 / 1024
	t.Logf("128KB echo with SACK: %v (%.1f MB/s round-trip), data integrity verified", elapsed, speed)
}
