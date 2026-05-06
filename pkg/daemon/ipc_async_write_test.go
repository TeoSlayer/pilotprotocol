// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// pairedConn returns two ends of a Unix-style pipe wrapped as net.Conn so we
// can test ipcConn writes against a real reader without spinning up the full
// IPC server.
func pairedConn(t *testing.T) (server, client net.Conn) {
	t.Helper()
	server, client = net.Pipe()
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})
	return server, client
}

// TestIPCConnAsyncWriteSerializesConcurrent confirms many concurrent writers
// produce in-order, length-framed messages on the wire — the same ordering
// guarantee the synchronous mutex provided.
func TestIPCConnAsyncWriteSerializesConcurrent(t *testing.T) {
	server, client := pairedConn(t)
	conn := newIPCConn(server)
	defer conn.Close()

	const writers = 16
	const perWriter = 25
	total := writers * perWriter

	// Drain the client side concurrently.
	var (
		readWG  sync.WaitGroup
		readErr error
		got     [][]byte
	)
	readWG.Add(1)
	go func() {
		defer readWG.Done()
		for i := 0; i < total; i++ {
			b, err := ipcutil.Read(client)
			if err != nil {
				readErr = err
				return
			}
			got = append(got, b)
		}
	}()

	var writeWG sync.WaitGroup
	for w := 0; w < writers; w++ {
		w := w
		writeWG.Add(1)
		go func() {
			defer writeWG.Done()
			for i := 0; i < perWriter; i++ {
				msg := []byte{byte(w), byte(i)}
				if err := conn.ipcWrite(msg); err != nil {
					t.Errorf("writer %d-%d: %v", w, i, err)
					return
				}
			}
		}()
	}
	writeWG.Wait()
	readWG.Wait()

	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if len(got) != total {
		t.Fatalf("read %d messages, want %d", len(got), total)
	}
	// We don't pin the across-writer interleaving (writers race), but each
	// per-writer sequence must arrive in order.
	last := make([]int, writers)
	for i := range last {
		last[i] = -1
	}
	for _, msg := range got {
		w, i := int(msg[0]), int(msg[1])
		if i != last[w]+1 {
			t.Fatalf("writer %d: out-of-order message %d after %d", w, i, last[w])
		}
		last[w] = i
	}
	for w := 0; w < writers; w++ {
		if last[w] != perWriter-1 {
			t.Fatalf("writer %d: stopped at %d, expected %d", w, last[w], perWriter-1)
		}
	}
}

// TestIPCConnAsyncWriteRejectsAfterClose verifies ipcWrite refuses to
// enqueue on a closed conn.
func TestIPCConnAsyncWriteRejectsAfterClose(t *testing.T) {
	server, _ := pairedConn(t)
	conn := newIPCConn(server)
	conn.Close()

	err := conn.ipcWrite([]byte("late"))
	if err == nil {
		t.Fatalf("ipcWrite on closed conn should fail")
	}
}

// TestIPCConnAsyncWriteBackpressure: a stuck reader fills the buffered
// channel; ipcWrite must return ErrIPCBackpressure rather than blocking
// indefinitely. This is the core property we want — a slow client cannot
// hold up the daemon.
func TestIPCConnAsyncWriteBackpressure(t *testing.T) {
	server, client := pairedConn(t)
	conn := newIPCConn(server)
	defer conn.Close()
	defer client.Close() // intentionally do NOT read — block forever

	// Fill the buffer + writer's in-flight slot. Buffer is `ipcSendBuffer`,
	// writer has 1 in-flight, plus the underlying net.Pipe blocks on first
	// Write since nothing reads. So we expect roughly buffer+1 to succeed
	// before backpressure.
	var (
		successes   atomic.Int64
		gotPressure atomic.Bool
	)
	deadline := time.After(3 * time.Second)
loop:
	for i := 0; i < ipcSendBuffer*2; i++ {
		select {
		case <-deadline:
			t.Fatalf("backpressure didn't trigger within 3s — successes so far: %d", successes.Load())
		default:
		}
		err := conn.ipcWrite([]byte{byte(i)})
		if err == nil {
			successes.Add(1)
			continue
		}
		if errors.Is(err, ErrIPCBackpressure) {
			gotPressure.Store(true)
			break loop
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if !gotPressure.Load() {
		t.Fatalf("expected backpressure error after filling buffer; got %d successes total", successes.Load())
	}
}

// TestIPCConnCloseDrainsBufferedMessages: messages enqueued before Close()
// reach the wire (best-effort) so we don't drop responses already committed
// to the channel before shutdown.
func TestIPCConnCloseDrainsBufferedMessages(t *testing.T) {
	server, client := pairedConn(t)
	conn := newIPCConn(server)

	const N = 20
	for i := 0; i < N; i++ {
		if err := conn.ipcWrite([]byte{byte(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Spawn reader before Close so writer can drain — Pipe blocks otherwise.
	var (
		got     [][]byte
		readWG  sync.WaitGroup
		readErr error
	)
	readWG.Add(1)
	go func() {
		defer readWG.Done()
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		for i := 0; i < N; i++ {
			b, err := ipcutil.Read(client)
			if err != nil {
				readErr = err
				return
			}
			got = append(got, b)
		}
	}()

	// Close after reader is running.
	time.Sleep(20 * time.Millisecond)
	conn.Close()

	readWG.Wait()
	if readErr != nil {
		t.Fatalf("read: %v (got %d/%d)", readErr, len(got), N)
	}
	if len(got) != N {
		t.Fatalf("drained %d messages, want %d", len(got), N)
	}
}
