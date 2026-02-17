package tests

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
)

func TestDataExchange(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Disable built-in dataexchange so the test can bind port 1001 itself
	disableDX := func(cfg *daemon.Config) { cfg.DisableDataExchange = true }
	a := env.AddDaemon(disableDX)
	b := env.AddDaemon(disableDX)

	// Server on A
	received := make(chan *dataexchange.Frame, 10)
	handler := func(conn net.Conn, frame *dataexchange.Frame) {
		received <- frame
		// Echo ACK
		dataexchange.WriteFrame(conn, &dataexchange.Frame{
			Type:    dataexchange.TypeText,
			Payload: []byte("ack"),
		})
	}

	srv := dataexchange.NewServer(a.Driver, handler)
	go srv.ListenAndServe()

	// Client on B
	c, err := dataexchange.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	t.Run("SendText", func(t *testing.T) {
		if err := c.SendText("hello data exchange"); err != nil {
			t.Fatalf("send text: %v", err)
		}
		select {
		case frame := <-received:
			if frame.Type != dataexchange.TypeText {
				t.Errorf("expected TEXT, got %s", dataexchange.TypeName(frame.Type))
			}
			if string(frame.Payload) != "hello data exchange" {
				t.Errorf("expected %q, got %q", "hello data exchange", string(frame.Payload))
			}
			t.Logf("received text: %s", string(frame.Payload))
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for text frame")
		}
		// Read ACK
		ack, err := c.Recv()
		if err != nil {
			t.Fatalf("recv ack: %v", err)
		}
		t.Logf("ack: %s", string(ack.Payload))
	})

	t.Run("SendJSON", func(t *testing.T) {
		if err := c.SendJSON([]byte(`{"key":"value"}`)); err != nil {
			t.Fatalf("send json: %v", err)
		}
		select {
		case frame := <-received:
			if frame.Type != dataexchange.TypeJSON {
				t.Errorf("expected JSON, got %s", dataexchange.TypeName(frame.Type))
			}
			t.Logf("received json: %s", string(frame.Payload))
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
		c.Recv() // drain ACK
	})

	t.Run("SendFile", func(t *testing.T) {
		if err := c.SendFile("test.txt", []byte("file contents here")); err != nil {
			t.Fatalf("send file: %v", err)
		}
		select {
		case frame := <-received:
			if frame.Type != dataexchange.TypeFile {
				t.Errorf("expected FILE, got %s", dataexchange.TypeName(frame.Type))
			}
			if frame.Filename != "test.txt" {
				t.Errorf("expected filename %q, got %q", "test.txt", frame.Filename)
			}
			if string(frame.Payload) != "file contents here" {
				t.Errorf("expected %q, got %q", "file contents here", string(frame.Payload))
			}
			t.Logf("received file: %s (%d bytes)", frame.Filename, len(frame.Payload))
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
		c.Recv() // drain ACK
	})

	t.Run("SendBinary", func(t *testing.T) {
		data := bytes.Repeat([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 256) // 1024 bytes
		if err := c.SendBinary(data); err != nil {
			t.Fatalf("send binary: %v", err)
		}
		select {
		case frame := <-received:
			if frame.Type != dataexchange.TypeBinary {
				t.Errorf("expected BINARY, got %s", dataexchange.TypeName(frame.Type))
			}
			if !bytes.Equal(frame.Payload, data) {
				t.Errorf("binary payload mismatch: got %d bytes, expected %d", len(frame.Payload), len(data))
			}
			t.Logf("received binary: %d bytes", len(frame.Payload))
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
		c.Recv() // drain ACK
	})
}

// TestDataExchangeLargePayload verifies sending a large binary payload through data exchange.
func TestDataExchangeLargePayload(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Disable built-in dataexchange so the test can bind port 1001 itself
	disableDX := func(cfg *daemon.Config) { cfg.DisableDataExchange = true }
	a := env.AddDaemon(disableDX)
	b := env.AddDaemon(disableDX)

	received := make(chan *dataexchange.Frame, 1)
	handler := func(conn net.Conn, frame *dataexchange.Frame) {
		received <- frame
		dataexchange.WriteFrame(conn, &dataexchange.Frame{
			Type:    dataexchange.TypeText,
			Payload: []byte("ack"),
		})
	}

	srv := dataexchange.NewServer(a.Driver, handler)
	go srv.ListenAndServe()

	c, err := dataexchange.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Send 64KB of binary data
	largeData := make([]byte, 64*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	if err := c.SendBinary(largeData); err != nil {
		t.Fatalf("send large binary: %v", err)
	}

	select {
	case frame := <-received:
		if !bytes.Equal(frame.Payload, largeData) {
			t.Errorf("large binary mismatch: got %d bytes, expected %d", len(frame.Payload), len(largeData))
		}
		t.Logf("received large binary: %d bytes", len(frame.Payload))
	case <-time.After(10 * time.Second):
		t.Fatal("timeout")
	}
}
