package tests

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzUnmarshal(f *testing.F) {
	// Seed with valid packet
	pkt := &protocol.Packet{
		Version: protocol.Version, Protocol: protocol.ProtoStream,
		Src: protocol.Addr{Network: 1, Node: 10}, Dst: protocol.Addr{Network: 1, Node: 20},
		SrcPort: 1000, DstPort: 7, Seq: 1, Ack: 0, Window: 64,
		Payload: []byte("hello"),
	}
	b, _ := pkt.Marshal()
	f.Add(b)
	f.Add(make([]byte, 34))                    // header only
	f.Add(make([]byte, 0))                     // empty
	f.Add(bytes.Repeat([]byte{0xFF}, 34))      // all ones
	f.Add(bytes.Repeat([]byte{0xFF}, 34+1024)) // large

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic regardless of input
		p, err := protocol.Unmarshal(data)
		if err != nil {
			return
		}
		// If parse succeeded, re-marshal must produce a valid packet
		out, err := p.Marshal()
		if err != nil {
			t.Fatalf("Marshal after successful Unmarshal: %v", err)
		}
		p2, err := protocol.Unmarshal(out)
		if err != nil {
			t.Fatalf("Unmarshal of re-marshalled packet: %v", err)
		}
		if p.Version != p2.Version || p.Flags != p2.Flags || p.Protocol != p2.Protocol {
			t.Fatal("round-trip mismatch on header fields")
		}
		if p.Src != p2.Src || p.Dst != p2.Dst {
			t.Fatal("round-trip mismatch on addresses")
		}
		if !bytes.Equal(p.Payload, p2.Payload) {
			t.Fatal("round-trip mismatch on payload")
		}
	})
}

func FuzzParseAddr(f *testing.F) {
	f.Add("0:0000.0000.0001")
	f.Add("1:0001.0000.000A")
	f.Add("")
	f.Add("not-an-addr")
	f.Add("65535:FFFF.FFFF.FFFF")
	f.Add("0:0000.0000.0000")
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat("a", 10000))

	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic
		_, _ = protocol.ParseAddr(s)
	})
}

func FuzzParseSocketAddr(f *testing.F) {
	f.Add("0:0000.0000.0001:7")
	f.Add("1:0001.0000.000A:443")
	f.Add("")
	f.Add("no-port")
	f.Add("0:0000.0000.0001:0")
	f.Add("0:0000.0000.0001:65535")
	f.Add("0:0000.0000.0001:-1")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = protocol.ParseSocketAddr(s)
	})
}

func FuzzPacketRoundTrip(f *testing.F) {
	f.Add(uint8(1), uint8(0x0F), uint8(1), uint16(0), uint32(1), uint16(0), uint32(2),
		uint16(1000), uint16(7), uint32(0), uint32(0), uint16(64), []byte("test"))

	f.Fuzz(func(t *testing.T, version, flags, proto uint8, srcNet uint16, srcNode uint32,
		dstNet uint16, dstNode uint32, srcPort, dstPort uint16, seq, ack uint32, window uint16, payload []byte) {

		if len(payload) > 0xFFFF {
			payload = payload[:0xFFFF]
		}

		pkt := &protocol.Packet{
			Version: version & 0x0F, Flags: flags & 0x0F, Protocol: proto,
			Src:     protocol.Addr{Network: srcNet, Node: srcNode},
			Dst:     protocol.Addr{Network: dstNet, Node: dstNode},
			SrcPort: srcPort, DstPort: dstPort,
			Seq: seq, Ack: ack, Window: window,
			Payload: payload,
		}

		data, err := pkt.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}

		got, err := protocol.Unmarshal(data)
		if pkt.Version != protocol.Version {
			// Non-current versions must be rejected.
			if err == nil {
				t.Fatalf("expected version error for version %d", pkt.Version)
			}
			return
		}
		if err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}

		if got.Version != pkt.Version {
			t.Errorf("Version: %d != %d", got.Version, pkt.Version)
		}
		if got.Flags != pkt.Flags {
			t.Errorf("Flags: %d != %d", got.Flags, pkt.Flags)
		}
		if got.Protocol != pkt.Protocol {
			t.Errorf("Protocol: %d != %d", got.Protocol, pkt.Protocol)
		}
		if got.Src != pkt.Src {
			t.Errorf("Src: %v != %v", got.Src, pkt.Src)
		}
		if got.Dst != pkt.Dst {
			t.Errorf("Dst: %v != %v", got.Dst, pkt.Dst)
		}
		if got.SrcPort != pkt.SrcPort || got.DstPort != pkt.DstPort {
			t.Errorf("Ports: %d/%d != %d/%d", got.SrcPort, got.DstPort, pkt.SrcPort, pkt.DstPort)
		}
		if got.Seq != pkt.Seq || got.Ack != pkt.Ack {
			t.Errorf("Seq/Ack: %d/%d != %d/%d", got.Seq, got.Ack, pkt.Seq, pkt.Ack)
		}
		if got.Window != pkt.Window {
			t.Errorf("Window: %d != %d", got.Window, pkt.Window)
		}
		if !bytes.Equal(got.Payload, pkt.Payload) {
			t.Error("Payload mismatch")
		}
	})
}

func FuzzAddrBinaryRoundTrip(f *testing.F) {
	f.Add(uint16(0), uint32(0))
	f.Add(uint16(1), uint32(1))
	f.Add(uint16(0xFFFF), uint32(0xFFFFFFFF))

	f.Fuzz(func(t *testing.T, network uint16, node uint32) {
		a := protocol.Addr{Network: network, Node: node}
		b := a.Marshal()
		got := protocol.UnmarshalAddr(b)
		if got != a {
			t.Fatalf("round-trip: %v != %v", got, a)
		}
	})
}

func FuzzAddrTextRoundTrip(f *testing.F) {
	f.Add(uint16(0), uint32(1))
	f.Add(uint16(1), uint32(0x00A3F291))
	f.Add(uint16(65535), uint32(0xFFFFFFFF))

	f.Fuzz(func(t *testing.T, network uint16, node uint32) {
		a := protocol.Addr{Network: network, Node: node}
		s := a.String()
		got, err := protocol.ParseAddr(s)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", s, err)
		}
		if got != a {
			t.Fatalf("round-trip: %v != %v", got, a)
		}
	})
}

func FuzzChecksumStability(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		c1 := protocol.Checksum(data)
		c2 := protocol.Checksum(data)
		if c1 != c2 {
			t.Fatalf("checksum instability: %d != %d", c1, c2)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case unit tests
// ---------------------------------------------------------------------------

func TestUnmarshalExactHeader(t *testing.T) {
	// 34 bytes with payload length = 0
	buf := make([]byte, 34)
	buf[0] = (protocol.Version << 4) // version=1, flags=0
	buf[1] = protocol.ProtoStream
	// payload length = 0 already
	// Compute checksum
	binary.BigEndian.PutUint32(buf[30:34], protocol.Checksum(buf))

	pkt, err := protocol.Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal exact header: %v", err)
	}
	if len(pkt.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(pkt.Payload))
	}
}

func TestUnmarshalPayloadLengthExceedsData(t *testing.T) {
	buf := make([]byte, 34)
	buf[0] = protocol.Version << 4
	binary.BigEndian.PutUint16(buf[2:4], 100) // claims 100 bytes of payload
	binary.BigEndian.PutUint32(buf[30:34], protocol.Checksum(buf))

	_, err := protocol.Unmarshal(buf)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestUnmarshalPayloadLengthMax(t *testing.T) {
	buf := make([]byte, 34)
	buf[0] = protocol.Version << 4
	binary.BigEndian.PutUint16(buf[2:4], 0xFFFF) // max payload length
	binary.BigEndian.PutUint32(buf[30:34], protocol.Checksum(buf))

	_, err := protocol.Unmarshal(buf)
	if err == nil {
		t.Fatal("expected error for max payload length with short buffer")
	}
}

func TestUnmarshalAllZero(t *testing.T) {
	buf := make([]byte, 34)
	// all zeros — version 0 is not supported, must be rejected.
	binary.BigEndian.PutUint32(buf[30:34], protocol.Checksum(buf))

	_, err := protocol.Unmarshal(buf)
	if err == nil {
		t.Fatal("expected version error for all-zero packet (version 0)")
	}
}

func TestUnmarshalAllFF(t *testing.T) {
	buf := bytes.Repeat([]byte{0xFF}, 34)
	_, err := protocol.Unmarshal(buf)
	// Checksum is extremely unlikely to match, so we expect an error
	if err == nil {
		t.Fatal("expected checksum mismatch for all-0xFF bytes")
	}
}

func TestParseAddrUnicode(t *testing.T) {
	_, err := protocol.ParseAddr("日本:0000.0000.0001")
	if err == nil {
		t.Fatal("expected error for unicode in network ID")
	}
}

func TestParseAddrNullBytes(t *testing.T) {
	_, err := protocol.ParseAddr("0\x00:0000.0000.0001")
	if err == nil {
		t.Fatal("expected error for null bytes in address")
	}
}

func TestParseAddrExtremelyLong(t *testing.T) {
	_, err := protocol.ParseAddr(strings.Repeat("x", 100000))
	if err == nil {
		t.Fatal("expected error for extremely long address")
	}
}

func TestParseAddrNetworkMismatch(t *testing.T) {
	// "1:0002.0000.0001" — decimal 1 but hex group 0002
	_, err := protocol.ParseAddr("1:0002.0000.0001")
	if err == nil {
		t.Fatal("expected error for network mismatch")
	}
}

func TestParseSocketAddrPort0(t *testing.T) {
	sa, err := protocol.ParseSocketAddr("0:0000.0000.0001:0")
	if err != nil {
		t.Fatalf("ParseSocketAddr port 0: %v", err)
	}
	if sa.Port != 0 {
		t.Fatalf("expected port 0, got %d", sa.Port)
	}
}

func TestParseSocketAddrPort65535(t *testing.T) {
	sa, err := protocol.ParseSocketAddr("0:0000.0000.0001:65535")
	if err != nil {
		t.Fatalf("ParseSocketAddr port 65535: %v", err)
	}
	if sa.Port != 65535 {
		t.Fatalf("expected port 65535, got %d", sa.Port)
	}
}

func TestParseSocketAddrNegative(t *testing.T) {
	_, err := protocol.ParseSocketAddr("0:0000.0000.0001:-1")
	if err == nil {
		t.Fatal("expected error for negative port")
	}
}

func TestFuzzPacketAllFlags(t *testing.T) {
	pkt := &protocol.Packet{
		Version: protocol.Version,
		Flags:   protocol.FlagSYN | protocol.FlagACK | protocol.FlagFIN | protocol.FlagRST,
		Src:     protocol.Addr{Network: 1, Node: 1},
		Dst:     protocol.Addr{Network: 1, Node: 2},
	}
	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal all flags: %v", err)
	}
	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal all flags: %v", err)
	}
	if got.Flags != 0x0F {
		t.Fatalf("expected all flags (0x0F), got 0x%02X", got.Flags)
	}
	if !got.HasFlag(protocol.FlagSYN) || !got.HasFlag(protocol.FlagACK) ||
		!got.HasFlag(protocol.FlagFIN) || !got.HasFlag(protocol.FlagRST) {
		t.Fatal("not all flags detected")
	}
}

func TestPacketVersionNot1(t *testing.T) {
	pkt := &protocol.Packet{
		Version: 2,
		Src:     protocol.Addr{Network: 1, Node: 1},
		Dst:     protocol.Addr{Network: 1, Node: 2},
	}
	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = protocol.Unmarshal(data)
	if err == nil {
		t.Fatal("expected error for unsupported version, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMarshalToOffset(t *testing.T) {
	a := protocol.Addr{Network: 0x1234, Node: 0xDEADBEEF}
	buf := make([]byte, 12) // offset 3 + 6 bytes addr = 9, but give some slack
	a.MarshalTo(buf, 3)
	got := protocol.UnmarshalAddr(buf[3:9])
	if got != a {
		t.Fatalf("MarshalTo offset: %v != %v", got, a)
	}
}

func TestUnmarshalTooShort(t *testing.T) {
	for size := 0; size < 34; size++ {
		_, err := protocol.Unmarshal(make([]byte, size))
		if err == nil {
			t.Fatalf("expected error for %d-byte input", size)
		}
	}
}

func TestMarshalPayloadTooLarge(t *testing.T) {
	pkt := &protocol.Packet{
		Version: protocol.Version,
		Src:     protocol.Addr{Network: 1, Node: 1},
		Dst:     protocol.Addr{Network: 1, Node: 2},
		Payload: make([]byte, 0x10000), // 64KB + 1
	}
	_, err := pkt.Marshal()
	if err == nil {
		t.Fatal("expected error for payload > 65535")
	}
}

func TestPacketHeaderSize(t *testing.T) {
	if protocol.PacketHeaderSize() != 34 {
		t.Fatalf("expected header size 34, got %d", protocol.PacketHeaderSize())
	}
}

func TestAddrSpecialValues(t *testing.T) {
	if !protocol.AddrZero.IsZero() {
		t.Fatal("AddrZero.IsZero() should be true")
	}
	if protocol.AddrRegistry.IsZero() {
		t.Fatal("AddrRegistry should not be zero")
	}
	bc := protocol.BroadcastAddr(1)
	if !bc.IsBroadcast() {
		t.Fatal("BroadcastAddr should be broadcast")
	}
	if bc.Network != 1 || bc.Node != 0xFFFFFFFF {
		t.Fatal("BroadcastAddr wrong values")
	}
}

func TestFuzzChecksumDeterministic(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	c := protocol.Checksum(data)
	for i := 0; i < 100; i++ {
		if protocol.Checksum(data) != c {
			t.Fatal("checksum not deterministic")
		}
	}
}

func TestFuzzChecksumEmpty(t *testing.T) {
	c := protocol.Checksum(nil)
	c2 := protocol.Checksum([]byte{})
	if c != c2 {
		t.Fatal("nil and empty checksum differ")
	}
}

func TestAddrStringRoundTrip(t *testing.T) {
	cases := []protocol.Addr{
		{Network: 0, Node: 0},
		{Network: 0, Node: 1},
		{Network: 1, Node: 0x00A3F291},
		{Network: 65535, Node: 0xFFFFFFFF},
		{Network: 100, Node: 0x00010002},
	}
	for _, a := range cases {
		s := a.String()
		got, err := protocol.ParseAddr(s)
		if err != nil {
			t.Errorf("ParseAddr(%q): %v", s, err)
			continue
		}
		if got != a {
			t.Errorf("round-trip %v: got %v from %q", a, got, s)
		}
	}
}

func TestSocketAddrStringRoundTrip(t *testing.T) {
	sa := protocol.SocketAddr{
		Addr: protocol.Addr{Network: 1, Node: 42},
		Port: 443,
	}
	s := sa.String()
	got, err := protocol.ParseSocketAddr(s)
	if err != nil {
		t.Fatalf("ParseSocketAddr(%q): %v", s, err)
	}
	if got.Addr != sa.Addr || got.Port != sa.Port {
		t.Fatalf("round-trip: %v != %v", got, sa)
	}
}

func TestParseAddrEdgeCases(t *testing.T) {
	bad := []string{
		"",
		":",
		"0:",
		":0000.0000.0001",
		"0:0000.0001",          // 2 groups
		"0:0000.0000.0001.000", // 4 groups
		"0:000.0000.0001",      // 3 digits
		"0:00000.0000.0001",    // 5 digits
		"-1:0000.0000.0001",    // negative
		"99999:0000.0000.0001", // > 65535
		"0:GGGG.0000.0001",     // invalid hex
	}
	for _, s := range bad {
		_, err := protocol.ParseAddr(s)
		if err == nil {
			t.Errorf("expected error for ParseAddr(%q)", s)
		}
	}
}

func TestParseSocketAddrEdgeCases(t *testing.T) {
	bad := []string{
		"",
		"no-colon",
		"0:0000.0000.0001:",      // empty port
		"0:0000.0000.0001:99999", // > 65535
		"0:0000.0000.0001:abc",   // non-numeric
		"0:0000.0000.0001:1.5",   // float
	}
	for _, s := range bad {
		_, err := protocol.ParseSocketAddr(s)
		if err == nil {
			t.Errorf("expected error for ParseSocketAddr(%q)", s)
		}
	}
}

// TestPacketLargePayload tests a packet at the max valid payload size.
func TestFuzzPacketLargePayload(t *testing.T) {
	pkt := &protocol.Packet{
		Version: protocol.Version,
		Src:     protocol.Addr{Network: 1, Node: 1},
		Dst:     protocol.Addr{Network: 1, Node: 2},
		Payload: make([]byte, 0xFFFF),
	}
	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal max payload: %v", err)
	}
	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal max payload: %v", err)
	}
	if len(got.Payload) != 0xFFFF {
		t.Fatalf("expected 65535 payload, got %d", len(got.Payload))
	}
}

func TestSetClearFlag(t *testing.T) {
	pkt := &protocol.Packet{}
	pkt.SetFlag(protocol.FlagSYN)
	if !pkt.HasFlag(protocol.FlagSYN) {
		t.Fatal("SetFlag failed")
	}
	pkt.SetFlag(protocol.FlagACK)
	if !pkt.HasFlag(protocol.FlagSYN) || !pkt.HasFlag(protocol.FlagACK) {
		t.Fatal("SetFlag should preserve existing flags")
	}
	pkt.ClearFlag(protocol.FlagSYN)
	if pkt.HasFlag(protocol.FlagSYN) {
		t.Fatal("ClearFlag failed")
	}
	if !pkt.HasFlag(protocol.FlagACK) {
		t.Fatal("ClearFlag should not affect other flags")
	}
}

func TestChecksumMaxUint32(t *testing.T) {
	// Ensure checksum handles large data without panic
	data := make([]byte, 65536)
	for i := range data {
		data[i] = byte(i)
	}
	c := protocol.Checksum(data)
	if c == 0 {
		// Extremely unlikely but not impossible; mainly checking no panic
		_ = c
	}
}

func TestAddrMarshalUnmarshalBoundary(t *testing.T) {
	cases := []protocol.Addr{
		{Network: 0, Node: 0},
		{Network: 0xFFFF, Node: 0xFFFFFFFF},
		{Network: 1, Node: 0},
		{Network: 0, Node: 1},
		{Network: 0x8000, Node: 0x80000000}, // sign bit boundaries
	}
	for _, a := range cases {
		b := a.Marshal()
		if len(b) != 6 {
			t.Fatalf("Marshal length: %d != 6", len(b))
		}
		got := protocol.UnmarshalAddr(b)
		if got != a {
			t.Fatalf("round-trip: %v != %v", got, a)
		}
	}
}

// Verify that version and flags don't overflow into each other.
func TestVersionFlagsPacking(t *testing.T) {
	for v := uint8(0); v <= 0x0F; v++ {
		for fl := uint8(0); fl <= 0x0F; fl++ {
			pkt := &protocol.Packet{Version: v, Flags: fl, Src: protocol.Addr{Node: 1}, Dst: protocol.Addr{Node: 2}}
			data, err := pkt.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			// Verify wire encoding: version in upper nibble, flags in lower nibble.
			if data[0]>>4 != v {
				t.Fatalf("wire version nibble: got %d, want %d", data[0]>>4, v)
			}
			if data[0]&0x0F != fl {
				t.Fatalf("wire flags nibble: got %d, want %d", data[0]&0x0F, fl)
			}
			// Only the current version round-trips through Unmarshal.
			if v == protocol.Version {
				got, err := protocol.Unmarshal(data)
				if err != nil {
					t.Fatalf("Unmarshal v=%d fl=%d: %v", v, fl, err)
				}
				if got.Version != v || got.Flags != fl {
					t.Fatalf("v=%d fl=%d -> v=%d fl=%d", v, fl, got.Version, got.Flags)
				}
			} else {
				_, err := protocol.Unmarshal(data)
				if err == nil {
					t.Fatalf("expected version error for v=%d fl=%d", v, fl)
				}
			}
		}
	}
}

// Verify large node IDs / high-bit addresses
func TestAddrHighBits(t *testing.T) {
	a := protocol.Addr{Network: 0xFFFF, Node: 0xFFFFFFFF}
	s := a.String()
	got, err := protocol.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr max addr: %v", err)
	}
	if got != a {
		t.Fatalf("max addr: %v != %v", got, a)
	}
}

// Verify that Window field actually round-trips in the packet.
func TestWindowFieldRoundTrip(t *testing.T) {
	for _, w := range []uint16{0, 1, 64, 0x7FFF, math.MaxUint16} {
		pkt := &protocol.Packet{
			Version: protocol.Version, Src: protocol.Addr{Node: 1}, Dst: protocol.Addr{Node: 2},
			Window: w,
		}
		data, err := pkt.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		got, err := protocol.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if got.Window != w {
			t.Fatalf("Window %d: got %d", w, got.Window)
		}
	}
}
