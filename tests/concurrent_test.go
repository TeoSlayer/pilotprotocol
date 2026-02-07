package tests

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConcurrentBidirectionalReadWrite tests simultaneous reads and writes
// on the same connection in both directions:
// 1. Two daemons, daemon A listens, daemon B dials
// 2. Both sides write 1KB blocks with incrementing sequence numbers
// 3. Both sides read and verify the other's sequence numbers
// 4. Run for 100 blocks each direction, verify no data corruption
func TestConcurrentBidirectionalReadWrite(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	t.Logf("daemon A: node=%d addr=%s", a.Daemon.NodeID(), a.Daemon.Addr())
	t.Logf("daemon B: node=%d addr=%s", b.Daemon.NodeID(), b.Daemon.Addr())

	const (
		numBlocks = 100
		blockSize = 1024
		port      = 3000
	)

	// A listens
	ln, err := a.Driver.Listen(port)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept goroutine
	type acceptResult struct {
		conn interface{ Read([]byte) (int, error); Write([]byte) (int, error); Close() error }
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept()
		acceptCh <- acceptResult{conn: conn, err: err}
	}()

	// B dials A
	connB, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connB.Close()

	// Wait for accept
	var connA interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	select {
	case res := <-acceptCh:
		if res.err != nil {
			t.Fatalf("accept: %v", res.err)
		}
		connA = res.conn
	case <-time.After(10 * time.Second):
		t.Fatal("accept timed out")
	}
	defer connA.Close()

	// makeBlock creates a 1KB block with a 4-byte sequence number prefix
	// and a marker byte ('A' or 'B') to identify the sender
	makeBlock := func(seq uint32, marker byte) []byte {
		block := make([]byte, blockSize)
		binary.BigEndian.PutUint32(block[0:4], seq)
		block[4] = marker
		// Fill rest with pattern based on seq for corruption detection
		for i := 5; i < blockSize; i++ {
			block[i] = byte((int(seq) + i) % 256)
		}
		return block
	}

	verifyBlock := func(data []byte, expectedMarker byte) (uint32, error) {
		if len(data) < 5 {
			return 0, fmt.Errorf("block too short: %d bytes", len(data))
		}
		seq := binary.BigEndian.Uint32(data[0:4])
		if data[4] != expectedMarker {
			return 0, fmt.Errorf("wrong marker: got %c, want %c", data[4], expectedMarker)
		}
		// Verify fill pattern
		for i := 5; i < len(data); i++ {
			expected := byte((int(seq) + i) % 256)
			if data[i] != expected {
				return 0, fmt.Errorf("corruption at offset %d in seq %d: got %d, want %d", i, seq, data[i], expected)
			}
		}
		return seq, nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	// Writer on A: sends blocks marked 'A'
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(0); i < numBlocks; i++ {
			block := makeBlock(i, 'A')
			if _, err := connA.Write(block); err != nil {
				errCh <- fmt.Errorf("A write seq %d: %w", i, err)
				return
			}
		}
	}()

	// Writer on B: sends blocks marked 'B'
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := uint32(0); i < numBlocks; i++ {
			block := makeBlock(i, 'B')
			if _, err := connB.Write(block); err != nil {
				errCh <- fmt.Errorf("B write seq %d: %w", i, err)
				return
			}
		}
	}()

	// Reader on A: reads blocks from B, verifies marker 'B'
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		var buf []byte
		readBuf := make([]byte, 4096)
		for received < numBlocks {
			n, err := connA.Read(readBuf)
			if err != nil {
				if received >= numBlocks {
					return
				}
				errCh <- fmt.Errorf("A read error after %d blocks: %w", received, err)
				return
			}
			buf = append(buf, readBuf[:n]...)

			// Extract complete blocks
			for len(buf) >= blockSize {
				_, err := verifyBlock(buf[:blockSize], 'B')
				if err != nil {
					errCh <- fmt.Errorf("A verify block %d: %w", received, err)
					return
				}
				received++
				buf = buf[blockSize:]
			}
		}
	}()

	// Reader on B: reads blocks from A, verifies marker 'A'
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		var buf []byte
		readBuf := make([]byte, 4096)
		for received < numBlocks {
			n, err := connB.Read(readBuf)
			if err != nil {
				if received >= numBlocks {
					return
				}
				errCh <- fmt.Errorf("B read error after %d blocks: %w", received, err)
				return
			}
			buf = append(buf, readBuf[:n]...)

			// Extract complete blocks
			for len(buf) >= blockSize {
				_, err := verifyBlock(buf[:blockSize], 'A')
				if err != nil {
					errCh <- fmt.Errorf("B verify block %d: %w", received, err)
					return
				}
				received++
				buf = buf[blockSize:]
			}
		}
	}()

	// Wait for all goroutines with a timeout
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		t.Logf("all %d blocks transferred in both directions successfully", numBlocks)
	case err := <-errCh:
		t.Fatalf("concurrent transfer error: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("concurrent bidirectional transfer timed out after 20s")
	}

	// Check for any deferred errors
	select {
	case err := <-errCh:
		t.Fatalf("deferred error: %v", err)
	default:
	}
}
