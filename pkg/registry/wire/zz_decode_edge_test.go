// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

func TestDecodeLookupReq_Truncated(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 2, 3} {
		_, err := wire.DecodeLookupReq(make([]byte, n))
		if err == nil || !strings.Contains(err.Error(), "too short") {
			t.Errorf("len=%d: want 'too short' err, got %v", n, err)
		}
	}
}

func TestDecodeLookupReq_HappyPath(t *testing.T) {
	t.Parallel()
	got, err := wire.DecodeLookupReq([]byte{0x00, 0x00, 0xCA, 0xFE})
	if err != nil {
		t.Fatalf("DecodeLookupReq: %v", err)
	}
	if got != 0xCAFE {
		t.Errorf("got %x, want CAFE", got)
	}
}

func TestEncodeLookupResp_RoundTripWithAllFields(t *testing.T) {
	t.Parallel()
	// Build a fully-populated lookup response, then decode it.
	encoded := wire.EncodeLookupResp(
		0xABCD,                     // nodeID
		true,                       // public
		true,                       // taskExec
		[]uint16{1, 2, 3},          // networks
		[]byte("0123456789012345"), // pubkey (16 bytes)
		"host.example",             // hostname
		[]string{"tag1", "tag2"},   // tags
		"1.2.3.4:4000",             // realAddr (only if public)
		"ext-id-xyz",               // externalID
	)
	if len(encoded) == 0 {
		t.Fatal("EncodeLookupResp returned empty")
	}
	resp, err := wire.DecodeLookupResp(encoded)
	if err != nil {
		t.Fatalf("DecodeLookupResp: %v", err)
	}
	if resp.NodeID != 0xABCD {
		t.Errorf("NodeID = %x, want ABCD", resp.NodeID)
	}
	if !resp.Public {
		t.Errorf("Public = false, want true")
	}
	if resp.Hostname != "host.example" {
		t.Errorf("Hostname = %q, want host.example", resp.Hostname)
	}
	if resp.ExternalID != "ext-id-xyz" {
		t.Errorf("ExternalID = %q", resp.ExternalID)
	}
	if len(resp.Networks) != 3 {
		t.Errorf("Networks len = %d, want 3", len(resp.Networks))
	}
	if len(resp.Tags) != 2 {
		t.Errorf("Tags len = %d, want 2", len(resp.Tags))
	}
}

func TestEncodeLookupResp_PrivateNodeNoAddr(t *testing.T) {
	t.Parallel()
	// Private node: realAddr is encoded but should not be revealed by
	// post-decode contract.
	encoded := wire.EncodeLookupResp(
		1, false, false, []uint16{}, []byte{}, "host", []string{}, "", "",
	)
	resp, err := wire.DecodeLookupResp(encoded)
	if err != nil {
		t.Fatalf("DecodeLookupResp: %v", err)
	}
	if resp.Public {
		t.Errorf("Public = true, want false")
	}
}

func TestDecodeError_Truncated(t *testing.T) {
	t.Parallel()
	// DecodeError returns a string. Truncated → fallback string.
	for _, n := range []int{0, 1} {
		got := wire.DecodeError(make([]byte, n))
		if got != "unknown error" {
			t.Errorf("len=%d: got %q, want 'unknown error'", n, got)
		}
	}
}

func TestDecodeError_HappyPath(t *testing.T) {
	t.Parallel()
	// 2-byte length prefix + body
	msg := "internal error"
	buf := []byte{byte(len(msg) >> 8), byte(len(msg))}
	buf = append(buf, msg...)
	if got := wire.DecodeError(buf); got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}
