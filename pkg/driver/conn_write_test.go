package driver

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// TestConnWriteChunksLargePayload verifies that Conn.Write splits payloads
// larger than the IPC message cap into multiple cmdSend messages so the
// daemon side never rejects oversized frames.
func TestConnWriteChunksLargePayload(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	ipc := &ipcClient{
		conn:      clientSide,
		handlers:  make(map[byte][]chan []byte),
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		acceptChs: make(map[uint16]chan []byte),
		dgCh:      make(chan *Datagram, 1),
		doneCh:    make(chan struct{}),
	}

	const connID uint32 = 42
	c := &Conn{id: connID, ipc: ipc, deadlineCh: make(chan struct{})}

	const payloadSize = 5 * 1024 * 1024 // 5 MB
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	var got []byte
	var chunks int
	var readErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = serverSide.SetReadDeadline(time.Now().Add(5 * time.Second))
		for len(got) < payloadSize {
			msg, err := ipcutil.Read(serverSide)
			if err != nil {
				if err != io.EOF {
					readErr = err
				}
				return
			}
			if len(msg) < 5 {
				readErr = io.ErrShortBuffer
				return
			}
			if msg[0] != cmdSend {
				readErr = io.ErrUnexpectedEOF
				return
			}
			gotID := binary.BigEndian.Uint32(msg[1:5])
			if gotID != connID {
				readErr = io.ErrUnexpectedEOF
				return
			}
			if len(msg) > ipcutil.MaxMessageSize {
				readErr = io.ErrShortBuffer
				return
			}
			chunks++
			got = append(got, msg[5:]...)
		}
	}()

	n, err := c.Write(payload)
	if err != nil {
		t.Fatalf("Write returned err: %v", err)
	}
	if n != payloadSize {
		t.Fatalf("Write returned n=%d, want %d", n, payloadSize)
	}

	// Close to unblock reader if it got everything already.
	_ = clientSide.Close()
	wg.Wait()

	if readErr != nil {
		t.Fatalf("reader err: %v", readErr)
	}
	if len(got) != payloadSize {
		t.Fatalf("reader got %d bytes, want %d", len(got), payloadSize)
	}
	if chunks < 2 {
		t.Fatalf("expected >=2 chunks for 5MB payload, got %d", chunks)
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatalf("byte %d: got %d, want %d", i, b, byte(i))
		}
	}
}

// TestConnWriteSinglePayloadNotSplit verifies that payloads that fit in one
// IPC message are still sent as a single cmdSend message.
func TestConnWriteSinglePayloadNotSplit(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	ipc := &ipcClient{
		conn:      clientSide,
		handlers:  make(map[byte][]chan []byte),
		recvChs:   make(map[uint32]chan []byte),
		pendRecv:  make(map[uint32][][]byte),
		acceptChs: make(map[uint16]chan []byte),
		dgCh:      make(chan *Datagram, 1),
		doneCh:    make(chan struct{}),
	}

	const connID uint32 = 7
	c := &Conn{id: connID, ipc: ipc, deadlineCh: make(chan struct{})}

	payload := []byte("hello world")

	var got []byte
	var chunks int
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		msg, err := ipcutil.Read(serverSide)
		if err != nil {
			return
		}
		chunks++
		got = append(got, msg[5:]...)
	}()

	if _, err := c.Write(payload); err != nil {
		t.Fatalf("Write err: %v", err)
	}
	<-done

	if chunks != 1 {
		t.Fatalf("expected 1 chunk, got %d", chunks)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}
