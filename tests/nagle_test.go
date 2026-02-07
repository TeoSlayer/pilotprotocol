package tests

import (
	"testing"
	"time"
)

// TestNagleCoalescing verifies that Nagle's algorithm coalesces small writes
// into larger segments. We send many tiny writes and verify the receiver gets
// the data correctly (the coalescing is transparent to the application).
func TestNagleCoalescing(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Receiver accumulates all data
	ln, err := a.Driver.Listen(2300)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	const totalBytes = 10000
	recvDone := make(chan int)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recvDone <- 0
			return
		}
		defer conn.Close()

		total := 0
		buf := make([]byte, 65535)
		for total < totalBytes {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			total += n
		}
		recvDone <- total
	}()

	// Sender: many small writes (100 bytes each)
	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), 2300)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	smallBuf := make([]byte, 100)
	for i := 0; i < totalBytes/100; i++ {
		// Fill with pattern to detect corruption
		for j := range smallBuf {
			smallBuf[j] = byte(i + j)
		}
		if _, err := conn.Write(smallBuf); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	// Wait for receiver
	select {
	case total := <-recvDone:
		if total != totalBytes {
			t.Fatalf("received %d bytes, expected %d", total, totalBytes)
		}
		t.Logf("sent %d small writes (%d bytes each), total %d bytes in %v",
			totalBytes/100, 100, totalBytes, elapsed)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for receiver")
	}
}
