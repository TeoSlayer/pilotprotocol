package tests

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
	"time"
)

// TestLargeWriteSegmentation verifies that a single large Write() call
// is automatically segmented into MSS-sized chunks by the daemon and
// reassembled correctly on the receiver side.
func TestLargeWriteSegmentation(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon()
	infoB := env.AddDaemon()

	daemonA := infoA.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	// Receiver on A: accumulates all data and sends SHA-256 hash back
	ln, err := drvA.Listen(2100)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	const dataSize = 64 * 1024 // 64 KB — well above MSS of 4096

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		h := sha256.New()
		buf := make([]byte, 65535)
		total := 0
		for total < dataSize {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			h.Write(buf[:n])
			total += n
		}

		// Send hash back
		conn.Write(h.Sum(nil))
	}()

	// Sender on B: single large Write() call
	conn, err := drvB.DialAddr(daemonA.Addr(), 2100)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Generate random data
	data := make([]byte, dataSize)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatalf("generate data: %v", err)
	}
	localHash := sha256.Sum256(data)

	// Send ALL data in a single Write() — the daemon should segment it
	start := time.Now()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	elapsed := time.Since(start)

	// Read hash back
	hashBuf := make([]byte, 32)
	n, err := conn.Read(hashBuf)
	if err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if n != 32 {
		t.Fatalf("expected 32-byte hash, got %d bytes", n)
	}

	// Verify data integrity
	if string(hashBuf[:32]) != string(localHash[:]) {
		t.Fatalf("hash mismatch: data corrupted during segmented transfer")
	}

	throughput := float64(dataSize) / elapsed.Seconds() / 1024 / 1024
	t.Logf("single Write() of %d bytes segmented and transferred in %v (%.2f MB/s)", dataSize, elapsed, throughput)
}

// TestMultipleLargeWrites verifies multiple large writes work correctly
// in sequence on the same connection.
func TestMultipleLargeWrites(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	infoA := env.AddDaemon()
	infoB := env.AddDaemon()

	daemonA := infoA.Daemon
	drvA := infoA.Driver
	drvB := infoB.Driver

	// Echo server on A
	ln, err := drvA.Listen(2200)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			conn.Write(buf[:n])
		}
	}()

	// Client on B
	conn, err := drvB.DialAddr(daemonA.Addr(), 2200)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send 3 large writes of varying sizes
	sizes := []int{8192, 16384, 32768} // 8KB, 16KB, 32KB — all above MSS
	for i, size := range sizes {
		data := make([]byte, size)
		if _, err := io.ReadFull(rand.Reader, data); err != nil {
			t.Fatalf("generate data %d: %v", i, err)
		}

		if _, err := conn.Write(data); err != nil {
			t.Fatalf("write %d (%d bytes): %v", i, size, err)
		}

		// Read echoed data back
		received := make([]byte, 0, size)
		buf := make([]byte, 65535)
		for len(received) < size {
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("read %d: %v (got %d/%d bytes)", i, err, len(received), size)
			}
			received = append(received, buf[:n]...)
		}

		if string(received) != string(data) {
			t.Fatalf("write %d: data mismatch (sent %d, received %d)", i, size, len(received))
		}
		t.Logf("write %d: %d bytes echoed correctly", i, size)
	}
}
