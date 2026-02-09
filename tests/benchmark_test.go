package tests

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"web4/pkg/daemon"
)

// setupBenchPair creates a test environment with two daemons and an established
// connection between them on the given port. Returns the sender conn, receiver
// conn, and a cleanup function.
func setupBenchPair(b *testing.B, port uint16, opts ...func(*daemon.Config)) (sender, receiver io.ReadWriteCloser) {
	b.Helper()
	env := NewTestEnv(b)

	a := env.AddDaemon(opts...)
	c := env.AddDaemon(opts...)

	ln, err := a.Driver.Listen(port)
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	acceptCh := make(chan io.ReadWriteCloser, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		acceptCh <- conn
	}()

	connSender, err := c.Driver.DialAddr(a.Daemon.Addr(), port)
	if err != nil {
		b.Fatalf("dial: %v", err)
	}

	select {
	case receiver = <-acceptCh:
	case <-time.After(5 * time.Second):
		b.Fatal("accept timeout")
	}

	return connSender, receiver
}

// BenchmarkBulkTransfer measures throughput for a 1 MB transfer using MSS-sized chunked writes.
func BenchmarkBulkTransfer(b *testing.B) {
	const totalSize = 1 << 20 // 1 MB
	chunkSize := daemon.MaxSegmentSize

	sender, receiver := setupBenchPair(b, 5000)
	defer sender.Close()
	defer receiver.Close()

	data := make([]byte, chunkSize)
	rand.Read(data)

	// Receiver goroutine: drain all data
	go func() {
		buf := make([]byte, 32*1024)
		for {
			if _, err := receiver.Read(buf); err != nil {
				return
			}
		}
	}()

	b.SetBytes(totalSize)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		written := 0
		for written < totalSize {
			n, err := sender.Write(data)
			if err != nil {
				b.Fatalf("write: %v", err)
			}
			written += n
		}
	}
}

// BenchmarkBulkTransferLargeWrite measures throughput for a 1 MB transfer
// using large Write() calls (512 KB each), exercising the daemon's auto-segmentation.
func BenchmarkBulkTransferLargeWrite(b *testing.B) {
	const totalSize = 1 << 20  // 1 MB total
	const writeSize = 512 * 1024 // 512 KB per write (under IPC 1 MB limit)

	sender, receiver := setupBenchPair(b, 5001)
	defer sender.Close()
	defer receiver.Close()

	data := make([]byte, writeSize)
	rand.Read(data)

	// Receiver goroutine: drain all data
	go func() {
		buf := make([]byte, 32*1024)
		for {
			if _, err := receiver.Read(buf); err != nil {
				return
			}
		}
	}()

	b.SetBytes(totalSize)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		written := 0
		for written < totalSize {
			if _, err := sender.Write(data); err != nil {
				b.Fatalf("write: %v", err)
			}
			written += writeSize
		}
	}
}

// BenchmarkBulkTransferSmallChunks measures throughput sending 64 KB in small
// (1 KB) chunks. Tests Nagle coalescing efficiency — small writes are buffered
// and coalesced into MSS-sized segments before sending.
func BenchmarkBulkTransferSmallChunks(b *testing.B) {
	const totalSize = 64 * 1024 // 64 KB
	const chunkSize = 1024       // 1 KB — sub-MSS, triggers Nagle coalescing

	sender, receiver := setupBenchPair(b, 5002)
	defer sender.Close()
	defer receiver.Close()

	data := make([]byte, chunkSize)
	rand.Read(data)

	// Receiver goroutine: drain all data
	go func() {
		buf := make([]byte, 32*1024)
		for {
			if _, err := receiver.Read(buf); err != nil {
				return
			}
		}
	}()

	b.SetBytes(totalSize)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		written := 0
		for written < totalSize {
			n, err := sender.Write(data)
			if err != nil {
				b.Fatalf("write: %v", err)
			}
			written += n
		}
	}
}

// BenchmarkEncryptedTransfer measures throughput for a 1 MB transfer over
// an encrypted tunnel (X25519 + AES-256-GCM).
func BenchmarkEncryptedTransfer(b *testing.B) {
	const totalSize = 1 << 20 // 1 MB
	chunkSize := daemon.MaxSegmentSize

	sender, receiver := setupBenchPair(b, 5003, func(cfg *daemon.Config) {
		cfg.Encrypt = true
	})
	defer sender.Close()
	defer receiver.Close()

	data := make([]byte, chunkSize)
	rand.Read(data)

	// Receiver goroutine: drain all data
	go func() {
		buf := make([]byte, 32*1024)
		for {
			if _, err := receiver.Read(buf); err != nil {
				return
			}
		}
	}()

	b.SetBytes(totalSize)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		written := 0
		for written < totalSize {
			n, err := sender.Write(data)
			if err != nil {
				b.Fatalf("write: %v", err)
			}
			written += n
		}
	}
}

// BenchmarkHTTPOverPilot measures a full HTTP request/response cycle over the
// overlay network, including connection setup, request, and response with body.
func BenchmarkHTTPOverPilot(b *testing.B) {
	env := NewTestEnv(b)
	a := env.AddDaemon()
	c := env.AddDaemon()

	ln, err := a.Driver.Listen(80)
	if err != nil {
		b.Fatalf("listen: %v", err)
	}

	body := bytes.Repeat([]byte("X"), 1024) // 1 KB response body
	mux := http.NewServeMux()
	mux.HandleFunc("/bench", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Write(body)
	})
	go http.Serve(ln, mux)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		conn, err := c.Driver.DialAddr(a.Daemon.Addr(), 80)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}

		req := "GET /bench HTTP/1.0\r\nHost: test\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			b.Fatalf("write: %v", err)
		}

		// Read full response
		var resp []byte
		buf := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				resp = append(resp, buf[:n]...)
			}
			if readErr != nil {
				break
			}
		}
		conn.Close()

		if len(resp) == 0 {
			b.Fatal("empty HTTP response")
		}
	}
}

// BenchmarkSmallMessages measures per-message overhead with 1000 small (64-byte)
// request-response round-trips per benchmark iteration.
func BenchmarkSmallMessages(b *testing.B) {
	const msgSize = 64
	const roundTrips = 1000

	sender, receiver := setupBenchPair(b, 5004)
	defer sender.Close()
	defer receiver.Close()

	msg := make([]byte, msgSize)
	rand.Read(msg)

	// Echo server on receiver side
	go func() {
		buf := make([]byte, msgSize)
		for {
			n, err := receiver.Read(buf)
			if err != nil {
				return
			}
			if _, err := receiver.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	b.SetBytes(int64(msgSize) * roundTrips * 2) // both directions
	b.ResetTimer()
	b.ReportAllocs()

	readBuf := make([]byte, msgSize)
	for i := 0; i < b.N; i++ {
		for j := 0; j < roundTrips; j++ {
			if _, err := sender.Write(msg); err != nil {
				b.Fatalf("write: %v", err)
			}
			if _, err := io.ReadFull(sender, readBuf); err != nil {
				b.Fatalf("read: %v", err)
			}
		}
	}
}
