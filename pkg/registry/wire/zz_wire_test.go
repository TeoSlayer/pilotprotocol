// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// --- ReadFrame / WriteFrame ---

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		msgType byte
		payload []byte
	}{
		{"heartbeat no payload", wire.MsgHeartbeat, nil},
		{"heartbeat ok", wire.MsgHeartbeatOK, []byte{1, 2, 3}},
		{"json passthrough", wire.MsgJSON, []byte(`{"cmd":"ping"}`)},
		{"error frame", wire.MsgError, wire.EncodeError("something went wrong")},
		{"empty payload", wire.MsgLookup, []byte{}},
		{"max type byte", 0xFE, bytes.Repeat([]byte{0xAA}, 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := wire.WriteFrame(&buf, tc.msgType, tc.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			gotType, gotPayload, err := wire.ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if gotType != tc.msgType {
				t.Errorf("type: got 0x%02x want 0x%02x", gotType, tc.msgType)
			}
			if !bytes.Equal(gotPayload, tc.payload) {
				t.Errorf("payload mismatch: got %v want %v", gotPayload, tc.payload)
			}
		})
	}
}

func TestReadFrameTooShort(t *testing.T) {
	t.Parallel()
	// Feed only 3 bytes — header needs 5.
	r := bytes.NewReader([]byte{0, 0, 1})
	_, _, err := wire.ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestReadFrameTooLarge(t *testing.T) {
	t.Parallel()
	// Craft a frame whose length field = MaxMessageSize + 1.
	var hdr [5]byte
	hdr[0] = 0x04 // big-endian 0x04000001 > 64 MiB
	hdr[1] = 0x00
	hdr[2] = 0x00
	hdr[3] = 0x01
	hdr[4] = wire.MsgJSON
	r := bytes.NewReader(hdr[:])
	_, _, err := wire.ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestReadFrameTruncatedPayload(t *testing.T) {
	t.Parallel()
	// Write a valid frame then truncate the stream mid-payload.
	var buf bytes.Buffer
	_ = wire.WriteFrame(&buf, wire.MsgLookupOK, bytes.Repeat([]byte{0xFF}, 64))
	// Remove the last 10 bytes.
	data := buf.Bytes()
	r := bytes.NewReader(data[:len(data)-10])
	_, _, err := wire.ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

// --- Heartbeat ---

func TestHeartbeatRoundTrip(t *testing.T) {
	t.Parallel()
	nodeID := uint32(0xDEADBEEF)
	sig := bytes.Repeat([]byte{0x42}, 64)

	enc := wire.EncodeHeartbeatReq(nodeID, sig)
	req, err := wire.DecodeHeartbeatReq(enc)
	if err != nil {
		t.Fatalf("DecodeHeartbeatReq: %v", err)
	}
	if req.NodeID != nodeID {
		t.Errorf("NodeID: got %d want %d", req.NodeID, nodeID)
	}
	if !bytes.Equal(req.Signature[:], sig) {
		t.Error("signature mismatch")
	}
}

func TestHeartbeatReqTooShort(t *testing.T) {
	t.Parallel()
	_, err := wire.DecodeHeartbeatReq(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short heartbeat req")
	}
}

func TestHeartbeatRespRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ts      int64
		warning bool
	}{
		{1700000000, false},
		{1700000001, true},
		{0, false},
		{-1, false},
	}
	for _, tc := range cases {
		enc := wire.EncodeHeartbeatResp(tc.ts, tc.warning)
		ts, warn, err := wire.DecodeHeartbeatResp(enc)
		if err != nil {
			t.Fatalf("DecodeHeartbeatResp: %v", err)
		}
		if ts != tc.ts {
			t.Errorf("ts: got %d want %d", ts, tc.ts)
		}
		if warn != tc.warning {
			t.Errorf("warning: got %v want %v", warn, tc.warning)
		}
	}
}

func TestHeartbeatRespTooShort(t *testing.T) {
	t.Parallel()
	_, _, err := wire.DecodeHeartbeatResp(make([]byte, 4))
	if err == nil {
		t.Fatal("expected error for short heartbeat resp")
	}
}

// --- Lookup ---

func TestLookupReqRoundTrip(t *testing.T) {
	t.Parallel()
	nodeID := uint32(12345)
	enc := wire.EncodeLookupReq(nodeID)
	got, err := wire.DecodeLookupReq(enc)
	if err != nil {
		t.Fatalf("DecodeLookupReq: %v", err)
	}
	if got != nodeID {
		t.Errorf("got %d want %d", got, nodeID)
	}
}

func TestLookupReqTooShort(t *testing.T) {
	t.Parallel()
	_, err := wire.DecodeLookupReq([]byte{1, 2})
	if err == nil {
		t.Fatal("expected error for short lookup req")
	}
}

func TestLookupRespRoundTrip(t *testing.T) {
	t.Parallel()
	nodeID := uint32(99)
	pubKey := bytes.Repeat([]byte{0xED}, 32)
	hostname := "mynode.local"
	tags := []string{"gpu", "arm64"}
	networks := []uint16{1, 2, 7}
	realAddr := "1.2.3.4:4000"
	extID := "user@example.com"

	enc := wire.EncodeLookupResp(nodeID, true, true, networks, pubKey, hostname, tags, realAddr, extID)
	r, err := wire.DecodeLookupResp(enc)
	if err != nil {
		t.Fatalf("DecodeLookupResp: %v", err)
	}
	if r.NodeID != nodeID {
		t.Errorf("NodeID: got %d want %d", r.NodeID, nodeID)
	}
	if !r.Public {
		t.Error("Public should be true")
	}
	if !r.TaskExec {
		t.Error("TaskExec should be true")
	}
	if len(r.Networks) != 3 || r.Networks[1] != 2 {
		t.Errorf("Networks: got %v", r.Networks)
	}
	if !bytes.Equal(r.PubKey, pubKey) {
		t.Error("PubKey mismatch")
	}
	if r.Hostname != hostname {
		t.Errorf("Hostname: got %q want %q", r.Hostname, hostname)
	}
	if len(r.Tags) != 2 || r.Tags[0] != "gpu" {
		t.Errorf("Tags: got %v", r.Tags)
	}
	if r.RealAddr != realAddr {
		t.Errorf("RealAddr: got %q want %q", r.RealAddr, realAddr)
	}
	if r.ExternalID != extID {
		t.Errorf("ExternalID: got %q want %q", r.ExternalID, extID)
	}
}

func TestLookupRespTooShort(t *testing.T) {
	t.Parallel()
	_, err := wire.DecodeLookupResp(make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for short lookup resp")
	}
}

// --- Resolve ---

func TestResolveReqRoundTrip(t *testing.T) {
	t.Parallel()
	nodeID := uint32(111)
	requesterID := uint32(222)
	sig := bytes.Repeat([]byte{0x55}, 64)

	enc := wire.EncodeResolveReq(nodeID, requesterID, sig)
	gotNode, gotReq, gotSig, err := wire.DecodeResolveReq(enc)
	if err != nil {
		t.Fatalf("DecodeResolveReq: %v", err)
	}
	if gotNode != nodeID {
		t.Errorf("nodeID: got %d want %d", gotNode, nodeID)
	}
	if gotReq != requesterID {
		t.Errorf("requesterID: got %d want %d", gotReq, requesterID)
	}
	if !bytes.Equal(gotSig, sig) {
		t.Error("signature mismatch")
	}
}

func TestResolveReqTooShort(t *testing.T) {
	t.Parallel()
	_, _, _, err := wire.DecodeResolveReq(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error for short resolve req")
	}
}

func TestResolveRespRoundTrip(t *testing.T) {
	t.Parallel()
	nodeID := uint32(333)
	realAddr := "10.0.0.1:4000"
	lanAddrs := []string{"192.168.1.1:4000", "172.16.0.1:4000"}
	keyAgeDays := 90

	enc := wire.EncodeResolveResp(nodeID, realAddr, lanAddrs, keyAgeDays)
	r, err := wire.DecodeResolveResp(enc)
	if err != nil {
		t.Fatalf("DecodeResolveResp: %v", err)
	}
	if r.NodeID != nodeID {
		t.Errorf("NodeID: got %d want %d", r.NodeID, nodeID)
	}
	if r.RealAddr != realAddr {
		t.Errorf("RealAddr: got %q want %q", r.RealAddr, realAddr)
	}
	if len(r.LANAddrs) != 2 || r.LANAddrs[1] != lanAddrs[1] {
		t.Errorf("LANAddrs: got %v want %v", r.LANAddrs, lanAddrs)
	}
	if r.KeyAgeDays != keyAgeDays {
		t.Errorf("KeyAgeDays: got %d want %d", r.KeyAgeDays, keyAgeDays)
	}
}

func TestResolveRespUnknownKeyAge(t *testing.T) {
	t.Parallel()
	enc := wire.EncodeResolveResp(1, "1.2.3.4:9000", nil, -1)
	r, err := wire.DecodeResolveResp(enc)
	if err != nil {
		t.Fatalf("DecodeResolveResp: %v", err)
	}
	if r.KeyAgeDays != -1 {
		t.Errorf("KeyAgeDays: got %d want -1", r.KeyAgeDays)
	}
}

func TestResolveRespTooShort(t *testing.T) {
	t.Parallel()
	_, err := wire.DecodeResolveResp(make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for short resolve resp")
	}
}

// --- Error ---

func TestErrorRoundTrip(t *testing.T) {
	t.Parallel()
	msg := "registry: node not found"
	enc := wire.EncodeError(msg)
	got := wire.DecodeError(enc)
	if got != msg {
		t.Errorf("DecodeError: got %q want %q", got, msg)
	}
}

func TestDecodeErrorEmpty(t *testing.T) {
	t.Parallel()
	got := wire.DecodeError(nil)
	if got == "" {
		t.Error("DecodeError(nil) should return a non-empty fallback")
	}
}

func TestDecodeErrorShort(t *testing.T) {
	t.Parallel()
	got := wire.DecodeError([]byte{0x00})
	if got == "" {
		t.Error("DecodeError with 1-byte payload should return fallback")
	}
}

func TestEncodeErrorLongMessage(t *testing.T) {
	t.Parallel()
	// Messages > 65000 bytes must be truncated.
	long := strings.Repeat("x", 70000)
	enc := wire.EncodeError(long)
	got := wire.DecodeError(enc)
	if len(got) > 65000 {
		t.Errorf("decoded message not truncated: len=%d", len(got))
	}
}

// --- JSON message framing ---

func TestWriteReadMessageRoundTrip(t *testing.T) {
	t.Parallel()
	msg := map[string]interface{}{
		"cmd":     "heartbeat",
		"node_id": float64(42),
	}
	var buf bytes.Buffer
	if err := wire.WriteMessage(&buf, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	got, err := wire.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got["cmd"] != msg["cmd"] {
		t.Errorf("cmd: got %v want %v", got["cmd"], msg["cmd"])
	}
}

func TestReadMessageEOF(t *testing.T) {
	t.Parallel()
	_, err := wire.ReadMessage(strings.NewReader(""))
	if err != io.EOF && err == nil {
		t.Error("expected EOF or error on empty reader")
	}
}

func TestReadMessageTruncated(t *testing.T) {
	t.Parallel()
	// Write a valid message then truncate it.
	var buf bytes.Buffer
	_ = wire.WriteMessage(&buf, map[string]interface{}{"x": "hello"})
	data := buf.Bytes()
	_, err := wire.ReadMessage(bytes.NewReader(data[:len(data)/2]))
	if err == nil {
		t.Fatal("expected error for truncated message")
	}
}
