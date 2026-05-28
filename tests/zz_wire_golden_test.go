// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/pilot-protocol/common/protocol"
)

// TestWireFormatGolden is the P6 wire-protocol invariance gate. It reads each
// committed golden frame under testdata/wire/, parses it via the live
// production decoders (where available) or layout-mirroring helpers, then
// re-marshals and asserts the byte sequence is unchanged.
//
// Any byte-level wire-format change MUST regenerate the corpus via
//
//	go run -tags=wirecorpus ./cmd/wire-gen
//
// and this requires explicit version-bump approval per VERIFICATION P6.
func TestWireFormatGolden(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		roundtrip func(t *testing.T, golden []byte) []byte
	}{
		{"l1-packet-syn", l1Roundtrip},
		{"l1-packet-data", l1Roundtrip},
		{"l1-packet-fin", l1Roundtrip},
		{"l1-packet-rst", l1Roundtrip},
		{"l1-packet-datagram", l1Roundtrip},

		{"l4-msg-discover", l4DiscoverRoundtrip},
		{"l4-msg-discover-reply-v4", l4VarIPRoundtripFor(protocol.BeaconMsgDiscoverReply)},
		{"l4-msg-discover-reply-v6", l4VarIPRoundtripFor(protocol.BeaconMsgDiscoverReply)},
		{"l4-msg-punch-request", l4PunchRequestRoundtrip},
		{"l4-msg-punch-command", l4VarIPRoundtripFor(protocol.BeaconMsgPunchCommand)},
		{"l4-msg-relay", l4RelayRoundtrip},
		{"l4-msg-relay-deliver", l4RelayDeliverRoundtrip},
		{"l4-msg-sync", l4SyncRoundtrip},
		{"l4-punch-pilp", l4PunchPILPRoundtrip},

		{"l5-key-exchange-auth", l5AuthRoundtrip},
		{"l5-key-exchange-unauth", l5UnauthRoundtrip},

		{"l6-encrypted-frame", l6EncryptedFrameRoundtrip},

		{"l7-sack-payload", l7SACKRoundtrip},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("..", "testdata", "wire", tc.name+".bin")
			golden, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s: read golden: %v", tc.name, err)
			}
			if len(golden) == 0 {
				t.Fatalf("%s: golden file is empty", tc.name)
			}

			got := tc.roundtrip(t, golden)

			if !bytes.Equal(got, golden) {
				t.Fatalf("%s: round-trip diverges from golden\n"+
					"  golden (%d bytes): %x\n"+
					"  re-marshaled (%d bytes): %x\n"+
					"  regenerate with: go run -tags=wirecorpus ./cmd/wire-gen",
					tc.name, len(golden), golden, len(got), got)
			}
		})
	}
}

// --- L1 ---

func l1Roundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	pkt, err := protocol.Unmarshal(append([]byte(nil), golden...))
	if err != nil {
		t.Fatalf("L1 unmarshal: %v", err)
	}
	out, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("L1 marshal: %v", err)
	}
	return out
}

// --- L4 ---
//
// Beacon UDP control messages have no exported Marshal/Unmarshal in pkg/beacon
// (server.go reads bytes directly off the conn). The helpers below mirror the
// exact byte layout enforced by the production handlers.

// l4DiscoverRoundtrip parses [type(1)][nodeID(4)] and re-emits.
func l4DiscoverRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) != 5 {
		t.Fatalf("L4 discover: got %d bytes, want 5", len(golden))
	}
	if golden[0] != protocol.BeaconMsgDiscover {
		t.Fatalf("L4 discover: type=0x%02X, want 0x%02X", golden[0], protocol.BeaconMsgDiscover)
	}
	nodeID := binary.BigEndian.Uint32(golden[1:5])

	out := make([]byte, 5)
	out[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(out[1:5], nodeID)
	return out
}

// l4VarIPRoundtripFor returns a roundtrip function for messages with the
// shared layout [type(1)][iplen(1)][IP(iplen)][port(2)] — used by both
// MsgDiscoverReply (0x02) and MsgPunchCommand (0x04).
func l4VarIPRoundtripFor(msgType byte) func(t *testing.T, golden []byte) []byte {
	return func(t *testing.T, golden []byte) []byte {
		t.Helper()
		if len(golden) < 4 {
			t.Fatalf("L4 var-ip: too short (%d bytes)", len(golden))
		}
		if golden[0] != msgType {
			t.Fatalf("L4 var-ip: type=0x%02X, want 0x%02X", golden[0], msgType)
		}
		ipLen := int(golden[1])
		if ipLen != 4 && ipLen != 16 {
			t.Fatalf("L4 var-ip: ipLen=%d, want 4 or 16", ipLen)
		}
		expected := 1 + 1 + ipLen + 2
		if len(golden) != expected {
			t.Fatalf("L4 var-ip: got %d bytes, want %d (ipLen=%d)", len(golden), expected, ipLen)
		}
		ip := append([]byte(nil), golden[2:2+ipLen]...)
		port := binary.BigEndian.Uint16(golden[2+ipLen:])

		out := make([]byte, 1+1+ipLen+2)
		out[0] = msgType
		out[1] = byte(ipLen)
		copy(out[2:2+ipLen], ip)
		binary.BigEndian.PutUint16(out[2+ipLen:], port)
		return out
	}
}

// l4PunchRequestRoundtrip parses [0x03][requesterID(4)][targetID(4)] and re-emits.
func l4PunchRequestRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) != 9 {
		t.Fatalf("L4 punch-request: got %d bytes, want 9", len(golden))
	}
	if golden[0] != protocol.BeaconMsgPunchRequest {
		t.Fatalf("L4 punch-request: type=0x%02X, want 0x%02X", golden[0], protocol.BeaconMsgPunchRequest)
	}
	requester := binary.BigEndian.Uint32(golden[1:5])
	target := binary.BigEndian.Uint32(golden[5:9])

	out := make([]byte, 9)
	out[0] = protocol.BeaconMsgPunchRequest
	binary.BigEndian.PutUint32(out[1:5], requester)
	binary.BigEndian.PutUint32(out[5:9], target)
	return out
}

// l4RelayRoundtrip parses [0x05][senderID(4)][destID(4)][payload]. The payload
// is itself an L1 packet — round-trip it through Unmarshal/Marshal so any
// inner-frame divergence is caught too.
func l4RelayRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) < 9 {
		t.Fatalf("L4 relay: too short (%d bytes)", len(golden))
	}
	if golden[0] != protocol.BeaconMsgRelay {
		t.Fatalf("L4 relay: type=0x%02X, want 0x%02X", golden[0], protocol.BeaconMsgRelay)
	}
	sender := binary.BigEndian.Uint32(golden[1:5])
	dest := binary.BigEndian.Uint32(golden[5:9])

	innerGolden := append([]byte(nil), golden[9:]...)
	innerPkt, err := protocol.Unmarshal(append([]byte(nil), innerGolden...))
	if err != nil {
		t.Fatalf("L4 relay: inner L1 unmarshal: %v", err)
	}
	innerOut, err := innerPkt.Marshal()
	if err != nil {
		t.Fatalf("L4 relay: inner L1 marshal: %v", err)
	}
	if !bytes.Equal(innerOut, innerGolden) {
		t.Fatalf("L4 relay: inner L1 frame diverges (len %d vs %d)", len(innerOut), len(innerGolden))
	}

	out := make([]byte, 1+4+4+len(innerOut))
	out[0] = protocol.BeaconMsgRelay
	binary.BigEndian.PutUint32(out[1:5], sender)
	binary.BigEndian.PutUint32(out[5:9], dest)
	copy(out[9:], innerOut)
	return out
}

// l4RelayDeliverRoundtrip parses [0x06][senderID(4)][payload].
func l4RelayDeliverRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) < 5 {
		t.Fatalf("L4 relay-deliver: too short (%d bytes)", len(golden))
	}
	if golden[0] != protocol.BeaconMsgRelayDeliver {
		t.Fatalf("L4 relay-deliver: type=0x%02X, want 0x%02X", golden[0], protocol.BeaconMsgRelayDeliver)
	}
	sender := binary.BigEndian.Uint32(golden[1:5])
	payload := append([]byte(nil), golden[5:]...)

	out := make([]byte, 1+4+len(payload))
	out[0] = protocol.BeaconMsgRelayDeliver
	binary.BigEndian.PutUint32(out[1:5], sender)
	copy(out[5:], payload)
	return out
}

// l4SyncRoundtrip parses [0x07][beaconID(4)][nodeCount(2)][nodeID(4)] x N.
func l4SyncRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) < 7 {
		t.Fatalf("L4 sync: too short (%d bytes)", len(golden))
	}
	if golden[0] != protocol.BeaconMsgSync {
		t.Fatalf("L4 sync: type=0x%02X, want 0x%02X", golden[0], protocol.BeaconMsgSync)
	}
	beaconID := binary.BigEndian.Uint32(golden[1:5])
	count := binary.BigEndian.Uint16(golden[5:7])
	expected := 7 + 4*int(count)
	if len(golden) != expected {
		t.Fatalf("L4 sync: got %d bytes, want %d (count=%d)", len(golden), expected, count)
	}

	nodeIDs := make([]uint32, count)
	for i := 0; i < int(count); i++ {
		nodeIDs[i] = binary.BigEndian.Uint32(golden[7+4*i : 7+4*i+4])
	}

	out := make([]byte, expected)
	out[0] = protocol.BeaconMsgSync
	binary.BigEndian.PutUint32(out[1:5], beaconID)
	binary.BigEndian.PutUint16(out[5:7], count)
	for i, id := range nodeIDs {
		binary.BigEndian.PutUint32(out[7+4*i:7+4*i+4], id)
	}
	return out
}

// l4PunchPILPRoundtrip checks the 4-byte PILP magic.
func l4PunchPILPRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) != 4 {
		t.Fatalf("L4 PILP: got %d bytes, want 4", len(golden))
	}
	if !bytes.Equal(golden, protocol.TunnelMagicPunch[:]) {
		t.Fatalf("L4 PILP: bytes=%x, want %x", golden, protocol.TunnelMagicPunch[:])
	}
	out := make([]byte, 4)
	copy(out, protocol.TunnelMagicPunch[:])
	return out
}

// --- L5 ---

// l5AuthRoundtrip parses [PILA(4)][nodeID(4)][x25519pub(32)][ed25519pub(32)][sig(64)].
// We DON'T re-sign — the corpus signature must be byte-identical, so the
// round-trip splits the frame into its components and re-assembles them.
func l5AuthRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) != 136 {
		t.Fatalf("L5 auth: got %d bytes, want 136", len(golden))
	}
	if !bytes.Equal(golden[0:4], protocol.TunnelMagicAuthEx[:]) {
		t.Fatalf("L5 auth: magic=%x, want %x", golden[0:4], protocol.TunnelMagicAuthEx[:])
	}

	nodeID := binary.BigEndian.Uint32(golden[4:8])
	x25519Pub := append([]byte(nil), golden[8:40]...)
	edPub := append([]byte(nil), golden[40:72]...)
	sig := append([]byte(nil), golden[72:136]...)

	out := make([]byte, 136)
	copy(out[0:4], protocol.TunnelMagicAuthEx[:])
	binary.BigEndian.PutUint32(out[4:8], nodeID)
	copy(out[8:40], x25519Pub)
	copy(out[40:72], edPub)
	copy(out[72:136], sig)
	return out
}

// l5UnauthRoundtrip parses [PILK(4)][nodeID(4)][x25519pub(32)].
func l5UnauthRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	if len(golden) != 40 {
		t.Fatalf("L5 unauth: got %d bytes, want 40", len(golden))
	}
	if !bytes.Equal(golden[0:4], protocol.TunnelMagicKeyEx[:]) {
		t.Fatalf("L5 unauth: magic=%x, want %x", golden[0:4], protocol.TunnelMagicKeyEx[:])
	}

	nodeID := binary.BigEndian.Uint32(golden[4:8])
	x25519Pub := append([]byte(nil), golden[8:40]...)

	out := make([]byte, 40)
	copy(out[0:4], protocol.TunnelMagicKeyEx[:])
	binary.BigEndian.PutUint32(out[4:8], nodeID)
	copy(out[8:40], x25519Pub)
	return out
}

// --- L6 ---

// l6EncryptedFrameRoundtrip parses [PILS(4)][senderID(4)][nonce(12)][ct+tag]
// and re-assembles. The ciphertext is treated as opaque — we don't re-encrypt
// (which would require the session key and produce the same bytes only if the
// nonce/key/AAD are identical to the corpus). The structural test ensures the
// envelope splits and recombines correctly.
func l6EncryptedFrameRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	const headerLen = 4 + 4 + 12
	if len(golden) <= headerLen {
		t.Fatalf("L6 encrypted: too short (%d bytes)", len(golden))
	}
	if !bytes.Equal(golden[0:4], protocol.TunnelMagicSecure[:]) {
		t.Fatalf("L6 encrypted: magic=%x, want %x", golden[0:4], protocol.TunnelMagicSecure[:])
	}

	senderID := binary.BigEndian.Uint32(golden[4:8])
	nonce := append([]byte(nil), golden[8:20]...)
	ct := append([]byte(nil), golden[20:]...)

	out := make([]byte, len(golden))
	copy(out[0:4], protocol.TunnelMagicSecure[:])
	binary.BigEndian.PutUint32(out[4:8], senderID)
	copy(out[8:20], nonce)
	copy(out[20:], ct)
	return out
}

// --- L7 ---

// l7SACKRoundtrip uses the production EncodeSACK / DecodeSACK pair.
func l7SACKRoundtrip(t *testing.T, golden []byte) []byte {
	t.Helper()
	blocks, ok := daemon.DecodeSACK(append([]byte(nil), golden...))
	if !ok {
		t.Fatalf("L7 SACK: DecodeSACK rejected golden")
	}
	out := daemon.EncodeSACK(blocks)
	if out == nil {
		t.Fatalf("L7 SACK: EncodeSACK returned nil")
	}
	return out
}

// TestWireGoldenCorpusComplete verifies the corpus directory contains exactly
// the set of frames TestWireFormatGolden exercises — no orphaned goldens, no
// missing files.
func TestWireGoldenCorpusComplete(t *testing.T) {
	t.Parallel()

	expected := map[string]bool{
		"l1-packet-syn.bin":            false,
		"l1-packet-data.bin":           false,
		"l1-packet-fin.bin":            false,
		"l1-packet-rst.bin":            false,
		"l1-packet-datagram.bin":       false,
		"l4-msg-discover.bin":          false,
		"l4-msg-discover-reply-v4.bin": false,
		"l4-msg-discover-reply-v6.bin": false,
		"l4-msg-punch-request.bin":     false,
		"l4-msg-punch-command.bin":     false,
		"l4-msg-relay.bin":             false,
		"l4-msg-relay-deliver.bin":     false,
		"l4-msg-sync.bin":              false,
		"l4-punch-pilp.bin":            false,
		"l5-key-exchange-auth.bin":     false,
		"l5-key-exchange-unauth.bin":   false,
		"l6-encrypted-frame.bin":       false,
		"l7-sack-payload.bin":          false,
	}

	entries, err := os.ReadDir(filepath.Join("..", "testdata", "wire"))
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	var unexpected []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".bin" {
			continue
		}
		if _, ok := expected[name]; ok {
			expected[name] = true
		} else {
			unexpected = append(unexpected, name)
		}
	}
	for name, seen := range expected {
		if !seen {
			t.Errorf("missing wire golden: %s", name)
		}
	}
	for _, name := range unexpected {
		t.Errorf("unexpected wire golden: %s (add a TestWireFormatGolden case or remove it)", name)
	}
}
