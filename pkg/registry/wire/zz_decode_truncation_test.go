// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// TestDecodeLookupResp_TruncationCascade walks every truncation
// boundary in DecodeLookupResp by encoding a fully-populated response
// then progressively trimming the payload from the back.
func TestDecodeLookupResp_TruncationCascade(t *testing.T) {
	t.Parallel()
	full := wire.EncodeLookupResp(
		0x1234,
		true,
		false,
		[]uint16{1, 2},
		[]byte("pubkey-32-bytes-AAAAAAAAAAAAAAAA"),
		"hostname",
		[]string{"tagA", "tagB"},
		"10.0.0.1:4000",
		"ext-id",
	)
	// Truncate to every shorter length and ensure decode either succeeds
	// (only happens at exact length boundaries) or returns a truncation
	// error. This exercises every "if off >= len(payload)" branch.
	for i := 0; i < len(full); i++ {
		_, err := wire.DecodeLookupResp(full[:i])
		if err == nil {
			continue // accidental valid prefix is fine
		}
		// Every error should contain "truncated" or "too short".
		if !strings.Contains(err.Error(), "truncated") &&
			!strings.Contains(err.Error(), "too short") {
			t.Errorf("len=%d: unexpected err %v", i, err)
		}
	}
}

// TestDecodeResolveResp_TruncationCascade does the same for ResolveResp.
func TestDecodeResolveResp_TruncationCascade(t *testing.T) {
	t.Parallel()
	full := wire.EncodeResolveResp(0x1234, "10.0.0.5:4000", []string{"192.168.1.10:4000"}, 7)
	for i := 0; i < len(full); i++ {
		_, err := wire.DecodeResolveResp(full[:i])
		if err == nil {
			continue
		}
		if !strings.Contains(err.Error(), "truncated") &&
			!strings.Contains(err.Error(), "too short") &&
			!strings.Contains(err.Error(), "decode") {
			t.Errorf("len=%d: unexpected err %v", i, err)
		}
	}
}

// TestDecodeResolveReq_Truncation drills the short-buffer branches.
func TestDecodeResolveReq_Truncation(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 4, 8, 16, 32, 64, 71} {
		_, _, _, err := wire.DecodeResolveReq(make([]byte, n))
		if err == nil {
			t.Errorf("len=%d: want error, got nil", n)
		}
	}
}

// TestDecodeHeartbeatResp_Truncation exercises the small response decoder.
func TestDecodeHeartbeatResp_Truncation(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 2, 3, 4, 5, 8} {
		_, _, err := wire.DecodeHeartbeatResp(make([]byte, n))
		if err == nil {
			t.Errorf("len=%d: want error, got nil", n)
		}
	}
}

// TestDecodeError_LengthExceedsBuffer covers the clamping branch where the
// length prefix lies about how much data follows.
func TestDecodeError_LengthExceedsBuffer(t *testing.T) {
	t.Parallel()
	// Length prefix says 100 bytes, but buffer only has 5 bytes of body.
	buf := []byte{0x00, 0x64, 'h', 'e', 'l', 'l', 'o'} // 0x0064 = 100
	got := wire.DecodeError(buf)
	if got != "hello" {
		t.Errorf("got %q, want 'hello' (clamped)", got)
	}
}

// TestEncodeError_OverlongMessageTruncated covers EncodeError's 65000-byte cap.
func TestEncodeError_OverlongMessageTruncated(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 70000)
	encoded := wire.EncodeError(long)
	// Encoded payload = 2-byte length + body. Body should be 65000 chars.
	if len(encoded) != 2+65000 {
		t.Errorf("encoded length = %d, want %d", len(encoded), 2+65000)
	}
	// Decode and ensure round-trip is the truncated form.
	if got := wire.DecodeError(encoded); len(got) != 65000 {
		t.Errorf("decoded length = %d, want 65000", len(got))
	}
}
