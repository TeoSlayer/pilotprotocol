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

func TestReadFrameWriteFrame_RoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	payload := []byte("hello-frame-body")
	if err := wire.WriteFrame(&buf, 0x42, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	msgType, got, err := wire.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msgType != 0x42 {
		t.Errorf("msgType = %x, want 0x42", msgType)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestReadFrame_EmptyPayload(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := wire.WriteFrame(&buf, 0x01, nil); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	msgType, payload, err := wire.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if msgType != 0x01 {
		t.Errorf("msgType = %x, want 0x01", msgType)
	}
	if len(payload) != 0 {
		t.Errorf("payload len = %d, want 0", len(payload))
	}
}

func TestReadFrame_HeaderTruncated(t *testing.T) {
	t.Parallel()
	_, _, err := wire.ReadFrame(bytes.NewReader([]byte{0x00, 0x01})) // 2 bytes, need 5
	if !errors.Is(err, io.ErrUnexpectedEOF) && err != io.EOF {
		t.Errorf("want EOF/ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadFrame_LengthZero(t *testing.T) {
	t.Parallel()
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], 0) // length = 0 → too short
	hdr[4] = 0x01
	_, _, err := wire.ReadFrame(bytes.NewReader(hdr[:]))
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("want 'too short', got %v", err)
	}
}

func TestReadFrame_LengthExceedsMax(t *testing.T) {
	t.Parallel()
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], wire.MaxMessageSize+1)
	_, _, err := wire.ReadFrame(bytes.NewReader(hdr[:]))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("want 'too large', got %v", err)
	}
}

func TestReadFrame_PayloadTruncated(t *testing.T) {
	t.Parallel()
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], 100) // claims 99 bytes of payload
	hdr[4] = 0x01
	_, _, err := wire.ReadFrame(bytes.NewReader(append(hdr[:], []byte("short")...)))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("want ErrUnexpectedEOF, got %v", err)
	}
}

func TestWriteFrame_HeaderWriteError(t *testing.T) {
	t.Parallel()
	bang := errors.New("hdr-fail")
	err := wire.WriteFrame(&failingWriter{err: bang}, 0x01, []byte("xx"))
	if !errors.Is(err, bang) {
		t.Errorf("want hdr-fail, got %v", err)
	}
}

func TestWriteFrame_PayloadWriteError(t *testing.T) {
	t.Parallel()
	bang := errors.New("payload-fail")
	// allow 5-byte header, fail body
	err := wire.WriteFrame(&shortWriter{allow: 5, err: bang}, 0x01, []byte("hello"))
	if !errors.Is(err, bang) {
		t.Errorf("want payload-fail, got %v", err)
	}
}
