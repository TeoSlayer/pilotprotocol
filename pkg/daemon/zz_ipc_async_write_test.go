// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
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
	t.Parallel()
	server, client := pairedConn(t)
	conn := newIPCConn(server, 0, false)
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
	t.Parallel()
	server, _ := pairedConn(t)
	conn := newIPCConn(server, 0, false)
	conn.Close()

	err := conn.ipcWrite([]byte("late"))
	if err == nil {
		t.Fatalf("ipcWrite on closed conn should fail")
	}
}

// TestIPCConnAsyncWriteBlocksOnFullBuffer: per issue #99, ipcWrite no
// longer returns ErrIPCBackpressure on a stuck reader — silent reply
// drops were the root cause of the §4.8 stress drain failure. The
// blocking contract is: ipcWrite waits for enqueue, conn-close, or a
// broken socket; concurrent daemon dispatch (handleClient now spawns
// per-request goroutines) means a stalled writer applies backpressure
// only to the one dispatcher pushing its reply, not to other in-flight
// requests.
//
// This test exercises the "blocked-then-unblocked-by-close" path: fill
// the channel, observe the next write blocks, then Close the conn and
// confirm the write returns ErrIPCClosed.
func TestIPCConnAsyncWriteBlocksUntilClose(t *testing.T) {
	t.Parallel()
	server, client := pairedConn(t)
	conn := newIPCConn(server, 0, false)
	defer client.Close() // intentionally do NOT read — block forever

	// Fill the buffer + writer's in-flight slot. ipcSendBuffer + 1
	// writes should succeed before the next one parks.
	for i := 0; i < ipcSendBuffer+1; i++ {
		// Each write should either succeed (enqueue) or, once we exceed
		// the channel, briefly block until we move on. We give each a
		// 200ms ceiling — anything longer means we're past the buffer
		// and into the new blocking regime, which is the next phase.
		done := make(chan error, 1)
		go func(i int) { done <- conn.ipcWrite([]byte{byte(i)}) }(i)
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("write %d failed: %v", i, err)
			}
		case <-time.After(200 * time.Millisecond):
			// Buffer is full — break here; the next phase asserts the
			// blocking + unblocking-on-close behaviour.
			i = ipcSendBuffer + 1
			break
		}
		if i >= ipcSendBuffer+1 {
			break
		}
	}

	// Now an additional write should park because the buffer is full
	// and the writer is blocked on a stuck Pipe.Write. We expect it to
	// remain blocked until Close() fires `done`, at which point it
	// returns ErrIPCClosed (no silent drop).
	parked := make(chan error, 1)
	go func() { parked <- conn.ipcWrite([]byte{0xFF}) }()

	// Confirm it really is parked — give it 100ms to find a slot,
	// which it shouldn't.
	select {
	case <-parked:
		t.Fatalf("ipcWrite did not block on full buffer — issue #99 contract violated")
	case <-time.After(100 * time.Millisecond):
	}

	// Close the conn — the parked write should unblock with ErrIPCClosed.
	conn.Close()
	select {
	case err := <-parked:
		if !errors.Is(err, ErrIPCClosed) {
			t.Fatalf("post-Close unblocked write returned %v, want ErrIPCClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ipcWrite did not unblock within 2s of Close()")
	}
}

// TestIPCConnCloseDrainsBufferedMessages: messages enqueued before Close()
// reach the wire (best-effort) so we don't drop responses already committed
// to the channel before shutdown.
func TestIPCConnCloseDrainsBufferedMessages(t *testing.T) {
	t.Parallel()
	server, client := pairedConn(t)
	conn := newIPCConn(server, 0, false)

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
