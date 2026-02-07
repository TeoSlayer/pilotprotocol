package tests

import (
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
	"time"
)

func TestSlidingWindowLargeTransfer(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Receiver on A: accumulates all data, sends SHA-256 hash back
	ln, err := a.Driver.Listen(2000)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		h := sha256.New()
		buf := make([]byte, 65535)
		total := 0
		for total < transferSize {
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

	// Sender on B: generate random data, send it, verify hash
	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 2000)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Generate random data
	data := make([]byte, transferSize)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatalf("generate data: %v", err)
	}
	localHash := sha256.Sum256(data)

	// Send in chunks
	start := time.Now()
	chunkSize := 4096
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if _, err := conn.Write(data[off:end]); err != nil {
			t.Fatalf("write at offset %d: %v", off, err)
		}
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

	// Verify
	if string(hashBuf[:32]) != string(localHash[:]) {
		t.Fatalf("hash mismatch: data corrupted during transfer")
	}

	throughput := float64(transferSize) / elapsed.Seconds() / 1024 / 1024
	t.Logf("transferred %d bytes in %v (%.2f MB/s)", transferSize, elapsed, throughput)
}

const transferSize = 256 * 1024 // 256 KB
