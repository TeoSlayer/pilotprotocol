package registry

import (
	"bytes"
	"math"
	"testing"
)

func TestWireFrameRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		msgType byte
		payload []byte
	}{
		{"empty payload", wireMsgHeartbeat, nil},
		{"small payload", wireMsgLookup, []byte{1, 2, 3, 4}},
		{"max type", wireMsgError, []byte("test error")},
		{"json passthrough", wireMsgJSON, []byte(`{"type":"heartbeat","node_id":42}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := wireWriteFrame(&buf, tt.msgType, tt.payload); err != nil {
				t.Fatalf("write frame: %v", err)
			}

			gotType, gotPayload, err := wireReadFrame(&buf)
			if err != nil {
				t.Fatalf("read frame: %v", err)
			}
			if gotType != tt.msgType {
				t.Fatalf("type: got 0x%02x, want 0x%02x", gotType, tt.msgType)
			}
			if !bytes.Equal(gotPayload, tt.payload) {
				t.Fatalf("payload: got %v, want %v", gotPayload, tt.payload)
			}
		})
	}
}

func TestWireFrameMultipleMessages(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		payload := []byte{byte(i), byte(i + 1)}
		if err := wireWriteFrame(&buf, byte(i), payload); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}

	for i := 0; i < 10; i++ {
		gotType, gotPayload, err := wireReadFrame(&buf)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if gotType != byte(i) {
			t.Fatalf("frame %d type: got 0x%02x, want 0x%02x", i, gotType, byte(i))
		}
		if len(gotPayload) != 2 || gotPayload[0] != byte(i) || gotPayload[1] != byte(i+1) {
			t.Fatalf("frame %d payload mismatch", i)
		}
	}
}

func TestWireFrameTooLarge(t *testing.T) {
	t.Parallel()

	// Write a frame claiming a payload larger than maxMessageSize
	var buf bytes.Buffer
	wireWriteFrame(&buf, wireMsgJSON, make([]byte, maxMessageSize+1))

	_, _, err := wireReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversized frame")
	}
}

func TestHeartbeatReqRoundTrip(t *testing.T) {
	t.Parallel()

	var sig [64]byte
	for i := range sig {
		sig[i] = byte(i)
	}

	payload := encodeHeartbeatReq(42, sig[:])
	req, err := decodeHeartbeatReq(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if req.NodeID != 42 {
		t.Fatalf("nodeID: got %d, want 42", req.NodeID)
	}
	if req.Signature != sig {
		t.Fatal("signature mismatch")
	}
}

func TestHeartbeatReqTooShort(t *testing.T) {
	t.Parallel()
	_, err := decodeHeartbeatReq([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short payload")
	}
}

func TestHeartbeatRespRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		unixTime         int64
		keyExpiryWarning bool
	}{
		{"no warning", 1700000000, false},
		{"with warning", 1700000000, true},
		{"zero time", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := encodeHeartbeatResp(tt.unixTime, tt.keyExpiryWarning)
			gotTime, gotWarning, err := decodeHeartbeatResp(payload)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotTime != tt.unixTime {
				t.Fatalf("time: got %d, want %d", gotTime, tt.unixTime)
			}
			if gotWarning != tt.keyExpiryWarning {
				t.Fatalf("warning: got %v, want %v", gotWarning, tt.keyExpiryWarning)
			}
		})
	}
}

func TestLookupReqRoundTrip(t *testing.T) {
	t.Parallel()

	payload := encodeLookupReq(12345)
	nodeID, err := decodeLookupReq(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if nodeID != 12345 {
		t.Fatalf("nodeID: got %d, want 12345", nodeID)
	}
}

func TestLookupRespRoundTrip(t *testing.T) {
	t.Parallel()

	pubKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	payload := encodeLookupResp(
		42,                         // nodeID
		true,                       // public
		true,                       // taskExec
		100,                        // poloScore
		[]uint16{1, 2, 3},          // networks
		pubKey,                     // pubKey
		"test-host",                // hostname
		[]string{"svc", "primary"}, // tags
		"10.0.0.1:4000",            // realAddr
		"ext-123",                  // externalID
	)

	result, err := decodeLookupResp(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if result.NodeID != 42 {
		t.Fatalf("NodeID: got %d, want 42", result.NodeID)
	}
	if !result.Public {
		t.Fatal("expected Public=true")
	}
	if !result.TaskExec {
		t.Fatal("expected TaskExec=true")
	}
	if result.PoloScore != 100 {
		t.Fatalf("PoloScore: got %d, want 100", result.PoloScore)
	}
	if len(result.Networks) != 3 || result.Networks[0] != 1 || result.Networks[2] != 3 {
		t.Fatalf("Networks: got %v, want [1,2,3]", result.Networks)
	}
	if !bytes.Equal(result.PubKey, pubKey) {
		t.Fatal("PubKey mismatch")
	}
	if result.Hostname != "test-host" {
		t.Fatalf("Hostname: got %q, want %q", result.Hostname, "test-host")
	}
	if len(result.Tags) != 2 || result.Tags[0] != "svc" || result.Tags[1] != "primary" {
		t.Fatalf("Tags: got %v", result.Tags)
	}
	if result.RealAddr != "10.0.0.1:4000" {
		t.Fatalf("RealAddr: got %q", result.RealAddr)
	}
	if result.ExternalID != "ext-123" {
		t.Fatalf("ExternalID: got %q", result.ExternalID)
	}
}

func TestLookupRespMinimal(t *testing.T) {
	t.Parallel()

	payload := encodeLookupResp(1, false, false, 0, nil, nil, "", nil, "", "")
	result, err := decodeLookupResp(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.NodeID != 1 {
		t.Fatalf("NodeID: got %d, want 1", result.NodeID)
	}
	if result.Public || result.TaskExec {
		t.Fatal("expected both flags false")
	}
	if len(result.Networks) != 0 {
		t.Fatal("expected empty networks")
	}
	if len(result.PubKey) != 0 {
		t.Fatal("expected empty pubkey")
	}
}

func TestLookupRespNegativePoloScore(t *testing.T) {
	t.Parallel()

	payload := encodeLookupResp(1, false, false, -50, nil, nil, "", nil, "", "")
	result, err := decodeLookupResp(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.PoloScore != -50 {
		t.Fatalf("PoloScore: got %d, want -50", result.PoloScore)
	}
}

func TestResolveReqRoundTrip(t *testing.T) {
	t.Parallel()

	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 100)
	}

	payload := encodeResolveReq(10, 20, sig)
	nodeID, requesterID, gotSig, err := decodeResolveReq(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if nodeID != 10 {
		t.Fatalf("nodeID: got %d, want 10", nodeID)
	}
	if requesterID != 20 {
		t.Fatalf("requesterID: got %d, want 20", requesterID)
	}
	if !bytes.Equal(gotSig, sig) {
		t.Fatal("signature mismatch")
	}
}

func TestResolveRespRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		nodeID     uint32
		realAddr   string
		lanAddrs   []string
		keyAgeDays int
	}{
		{"basic", 42, "10.0.0.1:4000", nil, 30},
		{"with LANs", 42, "10.0.0.1:4000", []string{"192.168.1.1:4000", "192.168.2.1:4000"}, 30},
		{"unknown key age", 42, "10.0.0.1:4000", nil, -1},
		{"zero key age", 42, "10.0.0.1:4000", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := encodeResolveResp(tt.nodeID, tt.realAddr, tt.lanAddrs, tt.keyAgeDays)
			result, err := decodeResolveResp(payload)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if result.NodeID != tt.nodeID {
				t.Fatalf("NodeID: got %d, want %d", result.NodeID, tt.nodeID)
			}
			if result.RealAddr != tt.realAddr {
				t.Fatalf("RealAddr: got %q, want %q", result.RealAddr, tt.realAddr)
			}
			if len(result.LANAddrs) != len(tt.lanAddrs) {
				t.Fatalf("LANAddrs length: got %d, want %d", len(result.LANAddrs), len(tt.lanAddrs))
			}
			for i, la := range result.LANAddrs {
				if la != tt.lanAddrs[i] {
					t.Fatalf("LANAddrs[%d]: got %q, want %q", i, la, tt.lanAddrs[i])
				}
			}
			if result.KeyAgeDays != tt.keyAgeDays {
				t.Fatalf("KeyAgeDays: got %d, want %d", result.KeyAgeDays, tt.keyAgeDays)
			}
		})
	}
}

func TestResolveRespMaxKeyAge(t *testing.T) {
	t.Parallel()

	// Verify math.MaxUint32 maps to -1
	payload := encodeResolveResp(1, "addr", nil, -1)
	result, err := decodeResolveResp(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.KeyAgeDays != -1 {
		t.Fatalf("KeyAgeDays: got %d, want -1", result.KeyAgeDays)
	}

	// Verify large positive value round-trips
	payload = encodeResolveResp(1, "addr", nil, int(math.MaxUint32-1))
	result, err = decodeResolveResp(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.KeyAgeDays != int(math.MaxUint32-1) {
		t.Fatalf("KeyAgeDays: got %d, want %d", result.KeyAgeDays, math.MaxUint32-1)
	}
}

func TestWireErrorRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		msg  string
	}{
		{"simple", "not found"},
		{"empty", ""},
		{"long", string(make([]byte, 1000))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := encodeWireError(tt.msg)
			got := decodeWireError(payload)
			if got != tt.msg {
				t.Fatalf("got %q, want %q", got, tt.msg)
			}
		})
	}
}

func TestWireErrorTruncation(t *testing.T) {
	t.Parallel()

	// Messages > 65000 are truncated
	longMsg := string(make([]byte, 70000))
	payload := encodeWireError(longMsg)
	got := decodeWireError(payload)
	if len(got) != 65000 {
		t.Fatalf("expected truncated to 65000, got %d", len(got))
	}
}

func TestWireProtocolNegotiationMagic(t *testing.T) {
	t.Parallel()

	// Verify the magic bytes are correct
	if wireMagic != [4]byte{0x50, 0x49, 0x4C, 0x54} {
		t.Fatalf("magic: got %v, want PILT", wireMagic)
	}
	// Verify magic != any valid JSON length prefix (which must be < maxMessageSize)
	magicAsLen := uint32(wireMagic[0])<<24 | uint32(wireMagic[1])<<16 | uint32(wireMagic[2])<<8 | uint32(wireMagic[3])
	if magicAsLen <= maxMessageSize {
		t.Fatalf("magic as length (%d) must be > maxMessageSize (%d) for protocol detection", magicAsLen, maxMessageSize)
	}
}

func BenchmarkEncodeHeartbeatReq(b *testing.B) {
	sig := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		encodeHeartbeatReq(42, sig)
	}
}

func BenchmarkDecodeHeartbeatReq(b *testing.B) {
	sig := make([]byte, 64)
	payload := encodeHeartbeatReq(42, sig)
	for i := 0; i < b.N; i++ {
		decodeHeartbeatReq(payload)
	}
}

func BenchmarkEncodeLookupResp(b *testing.B) {
	pubKey := make([]byte, 32)
	networks := []uint16{1, 2, 3}
	tags := []string{"svc", "primary"}
	for i := 0; i < b.N; i++ {
		encodeLookupResp(42, true, true, 100, networks, pubKey, "test-host", tags, "10.0.0.1:4000", "ext-123")
	}
}

func BenchmarkDecodeLookupResp(b *testing.B) {
	pubKey := make([]byte, 32)
	networks := []uint16{1, 2, 3}
	tags := []string{"svc", "primary"}
	payload := encodeLookupResp(42, true, true, 100, networks, pubKey, "test-host", tags, "10.0.0.1:4000", "ext-123")
	for i := 0; i < b.N; i++ {
		decodeLookupResp(payload)
	}
}

func BenchmarkWireFrameRoundTrip(b *testing.B) {
	payload := make([]byte, 68) // heartbeat size
	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		wireWriteFrame(&buf, wireMsgHeartbeat, payload)
		wireReadFrame(&buf)
	}
}
