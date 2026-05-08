// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestReadFrame_SizeCap verifies MaxFrameSize acceptance / rejection.
// Replaces the core assertion behind test_size_file_500mb_reject.sh —
// a 500 MiB frame must be rejected cleanly, while frames up to MaxFrameSize
// (256 MiB) are accepted.
func TestReadFrame_SizeCap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		length  uint32
		wantErr bool
	}{
		{"zero", 0, false},
		{"under_cap_small", 1024, false},
		{"just_under_cap", MaxFrameSize - 1, false},
		{"at_cap", MaxFrameSize, false},
		{"just_over_cap", MaxFrameSize + 1, true},
		{"way_over_cap", 1 << 30, true}, // 1 GiB
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build a header-only buffer; if accepted, ReadFrame will
			// then try to read `length` bytes — stop at the cap check
			// by providing exactly the header.
			var hdr [8]byte
			binary.BigEndian.PutUint32(hdr[0:4], TypeBinary)
			binary.BigEndian.PutUint32(hdr[4:8], tc.length)

			// For over-cap, ReadFrame should reject at the header.
			// For under-cap, it will block waiting for payload — use a
			// buffer of exactly `length` zero bytes so it completes.
			body := bytes.Repeat([]byte{0}, int(tc.length))
			r := bytes.NewReader(append(hdr[:], body...))
			_, err := ReadFrame(r)

			if tc.wantErr && err == nil {
				t.Fatalf("length=%d: expected error, got none", tc.length)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("length=%d: unexpected error: %v", tc.length, err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "too large") {
				t.Fatalf("length=%d: wrong error: %v (want 'too large')", tc.length, err)
			}
		})
	}
}

// TestWriteFrame_Roundtrip covers the basic Frame write/read contract
// used by send-file / send-message integration tests. Ensures file frames
// serialize their filename prefix correctly.
func TestWriteFrame_Roundtrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       *Frame
		wantName string
	}{
		{"text", &Frame{Type: TypeText, Payload: []byte("hello")}, ""},
		{"json", &Frame{Type: TypeJSON, Payload: []byte(`{"a":1}`)}, ""},
		{"file_with_name", &Frame{Type: TypeFile, Filename: "hi.txt", Payload: []byte("hi\n")}, "hi.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tc.in); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if got.Type != tc.in.Type {
				t.Fatalf("type mismatch: got %d want %d", got.Type, tc.in.Type)
			}
			if !bytes.Equal(got.Payload, tc.in.Payload) {
				t.Fatalf("payload mismatch: got %q want %q",
					string(got.Payload), string(tc.in.Payload))
			}
			if got.Filename != tc.wantName {
				t.Fatalf("filename: got %q want %q", got.Filename, tc.wantName)
			}
		})
	}
}

// TestReadFrame_FilenameInvariants covers the security-relevant
// filename checks — reject path traversal, reject over-long names.
func TestReadFrame_FilenameInvariants(t *testing.T) {
	t.Parallel()
	mkFrame := func(name string) []byte {
		namelen := uint16(len(name))
		payload := make([]byte, 2+len(name))
		binary.BigEndian.PutUint16(payload[0:2], namelen)
		copy(payload[2:], name)
		var hdr [8]byte
		binary.BigEndian.PutUint32(hdr[0:4], TypeFile)
		binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
		return append(hdr[:], payload...)
	}

	// Path traversal — forward slash.
	if _, err := ReadFrame(bytes.NewReader(mkFrame("../etc/passwd"))); err == nil {
		t.Fatal("path traversal name accepted")
	}
	// Path traversal — backslash (Windows).
	if _, err := ReadFrame(bytes.NewReader(mkFrame("..\\secret"))); err == nil {
		t.Fatal("backslash path accepted")
	}
	// Too-long filename.
	long := strings.Repeat("a", maxFilenameLen+1)
	if _, err := ReadFrame(bytes.NewReader(mkFrame(long))); err == nil {
		t.Fatal("over-length filename accepted")
	}
}
