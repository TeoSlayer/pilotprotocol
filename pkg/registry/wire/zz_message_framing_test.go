// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// failingWriter returns the supplied error on every Write call. Used to
// exercise the early-return branch of WriteRawMessage.
type failingWriter struct{ err error }

func (f *failingWriter) Write(p []byte) (int, error) { return 0, f.err }

// shortWriter accepts the first N bytes then errors. Used to fail the
// SECOND Write inside WriteRawMessage.
type shortWriter struct {
	allow int
	err   error
}

func (s *shortWriter) Write(p []byte) (int, error) {
	if s.allow >= len(p) {
		s.allow -= len(p)
		return len(p), nil
	}
	return 0, s.err
}

func TestWriteReadMessageRoundTrip(t *testing.T) {
	t.Parallel()
	msg := map[string]interface{}{
		"op":    "register",
		"email": "a@b.co",
		"port":  float64(4000), // json.Unmarshal turns numbers into float64
	}
	var buf bytes.Buffer
	if err := wire.WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	got, err := wire.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	for k, v := range msg {
		if got[k] != v {
			t.Errorf("key %q: got %v (%T), want %v (%T)", k, got[k], got[k], v, v)
		}
	}
}

func TestWriteMessageJSONEncodeError(t *testing.T) {
	t.Parallel()
	// channels can't be JSON-encoded → json.Marshal fails.
	bad := map[string]interface{}{"ch": make(chan int)}
	err := wire.WriteMessage(&bytes.Buffer{}, bad)
	if err == nil || !strings.Contains(err.Error(), "json encode") {
		t.Fatalf("want 'json encode' err, got %v", err)
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	t.Parallel()
	// Synthesise a length prefix > MaxMessageSize without writing the body.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], wire.MaxMessageSize+1)
	r := bytes.NewReader(lenBuf[:])
	_, err := wire.ReadMessage(r)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want 'too large' err, got %v", err)
	}
}

func TestReadMessageEOFOnPrefix(t *testing.T) {
	t.Parallel()
	// Empty reader → io.EOF on the length prefix read.
	_, err := wire.ReadMessage(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
}

func TestReadMessageTruncatedBody(t *testing.T) {
	t.Parallel()
	// 100-byte prefix but only 5 bytes of body → ErrUnexpectedEOF.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 100)
	r := bytes.NewReader(append(lenBuf[:], []byte("short")...))
	_, err := wire.ReadMessage(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadMessageBadJSON(t *testing.T) {
	t.Parallel()
	body := []byte("{not json")
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	r := bytes.NewReader(append(lenBuf[:], body...))
	_, err := wire.ReadMessage(r)
	if err == nil || !strings.Contains(err.Error(), "json decode") {
		t.Fatalf("want 'json decode' err, got %v", err)
	}
}

func TestWriteRawMessageHappyPath(t *testing.T) {
	t.Parallel()
	body := []byte(`{"ok":true}`)
	var buf bytes.Buffer
	if err := wire.WriteRawMessage(&buf, body); err != nil {
		t.Fatalf("WriteRawMessage: %v", err)
	}
	// Verify prefix
	if buf.Len() != 4+len(body) {
		t.Fatalf("buf len %d, want %d", buf.Len(), 4+len(body))
	}
	gotLen := binary.BigEndian.Uint32(buf.Bytes()[:4])
	if int(gotLen) != len(body) {
		t.Errorf("length prefix %d, want %d", gotLen, len(body))
	}
	if !bytes.Equal(buf.Bytes()[4:], body) {
		t.Errorf("body mismatch: got %q", buf.Bytes()[4:])
	}
}

func TestWriteRawMessageErrorOnPrefix(t *testing.T) {
	t.Parallel()
	bang := errors.New("boom")
	err := wire.WriteRawMessage(&failingWriter{err: bang}, []byte(`{}`))
	if !errors.Is(err, bang) {
		t.Fatalf("want boom, got %v", err)
	}
}

func TestWriteRawMessageErrorOnBody(t *testing.T) {
	t.Parallel()
	bang := errors.New("boom")
	// allow the 4-byte prefix, fail on the body write
	err := wire.WriteRawMessage(&shortWriter{allow: 4, err: bang}, []byte(`{"x":1}`))
	if !errors.Is(err, bang) {
		t.Fatalf("want boom on body write, got %v", err)
	}
}
