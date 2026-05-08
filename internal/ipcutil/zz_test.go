// SPDX-License-Identifier: AGPL-3.0-or-later

package ipcutil

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestReadWriteRoundTrip(t *testing.T) {
	t.Parallel()
	for _, payload := range [][]byte{
		nil,
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 10000),
	} {
		var buf bytes.Buffer
		if err := Write(&buf, payload); err != nil {
			t.Fatalf("Write(%d bytes): %v", len(payload), err)
		}
		got, err := Read(&buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(payload))
		}
	}
}

func TestWriteLengthPrefix(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	payload := []byte("abcde")
	if err := Write(&buf, payload); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4+len(payload) {
		t.Fatalf("buf len = %d, want %d", buf.Len(), 4+len(payload))
	}
	length := binary.BigEndian.Uint32(buf.Bytes()[:4])
	if length != uint32(len(payload)) {
		t.Fatalf("length prefix = %d, want %d", length, len(payload))
	}
}

func TestReadTooLargeRejected(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// Write length prefix claiming > MaxMessageSize
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, MaxMessageSize+1)
	buf.Write(lenBuf)

	_, err := Read(&buf)
	if err == nil {
		t.Fatal("expected too-large error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error %q missing 'too large'", err)
	}
}

func TestReadExactlyMaxSizeAccepted(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	// Length exactly == max, followed by that many zero bytes
	data := make([]byte, MaxMessageSize)
	if err := Write(&buf, data); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatalf("max-size read should succeed: %v", err)
	}
	if len(got) != MaxMessageSize {
		t.Fatalf("len = %d, want %d", len(got), MaxMessageSize)
	}
}

func TestReadTruncatedLength(t *testing.T) {
	t.Parallel()
	buf := bytes.NewReader([]byte{0x00, 0x00}) // only 2 bytes of length prefix
	_, err := Read(buf)
	if err == nil {
		t.Fatal("expected error on truncated length prefix")
	}
}

func TestReadTruncatedPayload(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, 100)
	buf.Write(lenBuf)
	buf.Write([]byte("only 20 bytes here..")) // payload truncated
	_, err := Read(&buf)
	if err == nil {
		t.Fatal("expected truncation error")
	}
}

// errWriter fails every write — exercises the Write error paths.
type errWriter struct {
	failAfter int
	calls     int
}

func (w *errWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls > w.failAfter {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

func TestWriteErrorOnLengthPrefix(t *testing.T) {
	t.Parallel()
	w := &errWriter{failAfter: 0}
	err := Write(w, []byte("data"))
	if err == nil {
		t.Fatal("expected error from failing writer on length prefix")
	}
}

func TestWriteErrorOnPayload(t *testing.T) {
	t.Parallel()
	w := &errWriter{failAfter: 1} // first write (length) succeeds, second (payload) fails
	err := Write(w, []byte("data"))
	if err == nil {
		t.Fatal("expected error from failing writer on payload")
	}
}
