package tests

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestAddrString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr protocol.Addr
		want string
	}{
		{protocol.Addr{Network: 0, Node: 0}, "0:0000.0000.0000"},
		{protocol.Addr{Network: 0, Node: 1}, "0:0000.0000.0001"},
		{protocol.Addr{Network: 0, Node: 0x002A}, "0:0000.0000.002A"},
		{protocol.Addr{Network: 1, Node: 0xF2910004}, "1:0001.F291.0004"},
		{protocol.Addr{Network: 23, Node: 1}, "23:0017.0000.0001"},
		{protocol.BroadcastAddr(0), "0:0000.FFFF.FFFF"},
		{protocol.BroadcastAddr(5), "5:0005.FFFF.FFFF"},
	}

	for _, tt := range tests {
		got := tt.addr.String()
		if got != tt.want {
			t.Errorf("Addr{%d, 0x%08X}.String() = %q, want %q", tt.addr.Network, tt.addr.Node, got, tt.want)
		}
	}
}

func TestAddrParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  protocol.Addr
	}{
		{"0:0000.0000.0000", protocol.Addr{Network: 0, Node: 0}},
		{"0:0000.0000.0001", protocol.Addr{Network: 0, Node: 1}},
		{"0:0000.0000.002A", protocol.Addr{Network: 0, Node: 0x002A}},
		{"1:0001.F291.0004", protocol.Addr{Network: 1, Node: 0xF2910004}},
		{"23:0017.0000.0001", protocol.Addr{Network: 23, Node: 1}},
	}

	for _, tt := range tests {
		got, err := protocol.ParseAddr(tt.input)
		if err != nil {
			t.Errorf("ParseAddr(%q) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseAddr(%q) = {%d, 0x%08X}, want {%d, 0x%08X}",
				tt.input, got.Network, got.Node, tt.want.Network, tt.want.Node)
		}
	}
}

func TestAddrRoundTrip(t *testing.T) {
	t.Parallel()
	addrs := []protocol.Addr{
		{Network: 0, Node: 0},
		{Network: 0, Node: 1},
		{Network: 0, Node: 42},
		{Network: 1, Node: 0xF2910004},
		{Network: 23, Node: 1},
		{Network: 65535, Node: 0xFFFFFFFF},
	}

	for _, addr := range addrs {
		s := addr.String()
		parsed, err := protocol.ParseAddr(s)
		if err != nil {
			t.Errorf("round-trip failed for %v: String()=%q, parse error: %v", addr, s, err)
			continue
		}
		if parsed != addr {
			t.Errorf("round-trip failed: %v -> %q -> %v", addr, s, parsed)
		}
	}
}

func TestAddrParseErrors(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"0",
		"0:0000",
		"0:0000.0000",
		"0:0000.0000.0000.0000",
		"0:000.0000.0000",
		"0:0000.000.0000",
		"99999:0000.0000.0000",
		"0:ZZZZ.0000.0000",
		"1:0000.0000.0001", // network mismatch: decimal 1 != hex 0x0000
	}

	for _, s := range bad {
		_, err := protocol.ParseAddr(s)
		if err == nil {
			t.Errorf("ParseAddr(%q) should have failed", s)
		}
	}
}

func TestAddrMarshalUnmarshal(t *testing.T) {
	t.Parallel()
	addrs := []protocol.Addr{
		{Network: 0, Node: 0},
		{Network: 0, Node: 1},
		{Network: 1, Node: 0xF2910004},
		{Network: 0xFFFF, Node: 0xFFFFFFFF},
	}

	for _, addr := range addrs {
		b := addr.Marshal()
		if len(b) != protocol.AddrSize {
			t.Fatalf("Marshal() returned %d bytes, want %d", len(b), protocol.AddrSize)
		}
		got := protocol.UnmarshalAddr(b)
		if got != addr {
			t.Errorf("binary round-trip failed: %v -> %v", addr, got)
		}
	}
}

func TestAddrSpecialPredicates(t *testing.T) {
	t.Parallel()
	if !protocol.AddrZero.IsZero() {
		t.Error("AddrZero.IsZero() should be true")
	}
	if protocol.AddrRegistry.IsZero() {
		t.Error("AddrRegistry.IsZero() should be false")
	}
	if !protocol.BroadcastAddr(0).IsBroadcast() {
		t.Error("BroadcastAddr(0).IsBroadcast() should be true")
	}
	if protocol.AddrRegistry.IsBroadcast() {
		t.Error("AddrRegistry.IsBroadcast() should be false")
	}
}

func TestSocketAddrRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		addr  protocol.Addr
		port  uint16
	}{
		{"0:0000.0000.0001:1000", protocol.Addr{Network: 0, Node: 1}, 1000},
		{"1:0001.F291.0004:80", protocol.Addr{Network: 1, Node: 0xF2910004}, 80},
		{"0:0000.0000.002A:65535", protocol.Addr{Network: 0, Node: 42}, 65535},
	}

	for _, tt := range tests {
		sa, err := protocol.ParseSocketAddr(tt.input)
		if err != nil {
			t.Errorf("ParseSocketAddr(%q) error: %v", tt.input, err)
			continue
		}
		if sa.Addr != tt.addr || sa.Port != tt.port {
			t.Errorf("ParseSocketAddr(%q) = {%v, %d}, want {%v, %d}",
				tt.input, sa.Addr, sa.Port, tt.addr, tt.port)
		}

		s := sa.String()
		sa2, err := protocol.ParseSocketAddr(s)
		if err != nil {
			t.Errorf("round-trip parse of %q failed: %v", s, err)
			continue
		}
		if sa2 != sa {
			t.Errorf("round-trip failed: %v -> %q -> %v", sa, s, sa2)
		}
	}
}

// --- Packet tests ---

func TestPacketRoundTrip(t *testing.T) {
	t.Parallel()
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		SrcPort:  49152,
		DstPort:  1000,
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	if len(data) != protocol.PacketHeaderSize() {
		t.Fatalf("Marshal() returned %d bytes, want %d (no payload)", len(data), protocol.PacketHeaderSize())
	}

	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Version != pkt.Version {
		t.Errorf("Version = %d, want %d", got.Version, pkt.Version)
	}
	if got.Flags != pkt.Flags {
		t.Errorf("Flags = 0x%X, want 0x%X", got.Flags, pkt.Flags)
	}
	if got.Src != pkt.Src {
		t.Errorf("Src = %v, want %v", got.Src, pkt.Src)
	}
	if got.Dst != pkt.Dst {
		t.Errorf("Dst = %v, want %v", got.Dst, pkt.Dst)
	}
	if got.SrcPort != pkt.SrcPort {
		t.Errorf("SrcPort = %d, want %d", got.SrcPort, pkt.SrcPort)
	}
	if got.DstPort != pkt.DstPort {
		t.Errorf("DstPort = %d, want %d", got.DstPort, pkt.DstPort)
	}
}

func TestPacketWithPayload(t *testing.T) {
	t.Parallel()
	payload := []byte("hello from agent")

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		SrcPort:  49152,
		DstPort:  1000,
		Seq:      1,
		Ack:      1,
		Payload:  payload,
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	expected := protocol.PacketHeaderSize() + len(payload)
	if len(data) != expected {
		t.Fatalf("Marshal() returned %d bytes, want %d", len(data), expected)
	}

	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("Payload = %q, want %q", got.Payload, payload)
	}
}

func TestPacketAllFlags(t *testing.T) {
	t.Parallel()
	flags := []uint8{protocol.FlagSYN, protocol.FlagACK, protocol.FlagFIN, protocol.FlagRST, protocol.FlagSYN | protocol.FlagACK}

	for _, f := range flags {
		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    f,
			Protocol: protocol.ProtoStream,
			Src:      protocol.Addr{Network: 0, Node: 1},
			Dst:      protocol.Addr{Network: 0, Node: 2},
		}

		data, err := pkt.Marshal()
		if err != nil {
			t.Fatalf("Marshal(flags=0x%X) error: %v", f, err)
		}

		got, err := protocol.Unmarshal(data)
		if err != nil {
			t.Fatalf("Unmarshal(flags=0x%X) error: %v", f, err)
		}

		if got.Flags != f {
			t.Errorf("flags: got 0x%X, want 0x%X", got.Flags, f)
		}
	}
}

func TestPacketChecksumCorruption(t *testing.T) {
	t.Parallel()
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		Payload:  []byte("test data"),
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	data[protocol.PacketHeaderSize()] ^= 0xFF

	_, err = protocol.Unmarshal(data)
	if err == nil {
		t.Error("Unmarshal should fail on corrupted packet")
	}
}

func TestPacketLargePayload(t *testing.T) {
	t.Parallel()
	payload := make([]byte, 65535)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		Payload:  payload,
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if !bytes.Equal(got.Payload, payload) {
		t.Error("large payload round-trip mismatch")
	}
}

func TestPacketSeqAck(t *testing.T) {
	t.Parallel()
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		Seq:      0xDEADBEEF,
		Ack:      0xCAFEBABE,
		Payload:  []byte("data"),
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Seq != 0xDEADBEEF {
		t.Errorf("Seq = 0x%08X, want 0xDEADBEEF", got.Seq)
	}
	if got.Ack != 0xCAFEBABE {
		t.Errorf("Ack = 0x%08X, want 0xCAFEBABE", got.Ack)
	}
}

// --- Checksum tests ---

func TestChecksumDeterministic(t *testing.T) {
	t.Parallel()
	data := []byte("pilot protocol test data")
	c1 := protocol.Checksum(data)
	c2 := protocol.Checksum(data)
	if c1 != c2 {
		t.Errorf("Checksum not deterministic: 0x%08X != 0x%08X", c1, c2)
	}
}

func TestChecksumDifferentData(t *testing.T) {
	t.Parallel()
	c1 := protocol.Checksum([]byte("hello"))
	c2 := protocol.Checksum([]byte("world"))
	if c1 == c2 {
		t.Error("different data should produce different checksums")
	}
}

func TestChecksumEmpty(t *testing.T) {
	t.Parallel()
	c := protocol.Checksum(nil)
	if c != 0 {
		t.Fatalf("checksum of nil = %d, want 0", c)
	}
	c2 := protocol.Checksum([]byte{})
	if c2 != 0 {
		t.Fatalf("checksum of empty = %d, want 0", c2)
	}
}

func TestAddrMarshalTo(t *testing.T) {
	t.Parallel()
	buf := make([]byte, 20)
	a := protocol.Addr{Network: 0x0001, Node: 0x00020003}
	a.MarshalTo(buf, 7)
	got := protocol.UnmarshalAddr(buf[7:13])
	if got != a {
		t.Fatalf("MarshalTo roundtrip: got %v, want %v", got, a)
	}
}

func TestParseSocketAddrErrors(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"noport",
		"1:0001.00A3.F291:",     // empty port
		"1:0001.00A3.F291:99999", // port > 65535
	}
	for _, s := range bad {
		_, err := protocol.ParseSocketAddr(s)
		if err == nil {
			t.Errorf("ParseSocketAddr(%q) should fail", s)
		}
	}
}

func TestPacketFlagOperations(t *testing.T) {
	t.Parallel()
	p := &protocol.Packet{}
	p.SetFlag(protocol.FlagSYN)
	if !p.HasFlag(protocol.FlagSYN) {
		t.Fatal("expected SYN set")
	}
	p.SetFlag(protocol.FlagACK)
	if !p.HasFlag(protocol.FlagACK) {
		t.Fatal("expected ACK set")
	}
	p.ClearFlag(protocol.FlagSYN)
	if p.HasFlag(protocol.FlagSYN) {
		t.Fatal("expected SYN cleared")
	}
	if !p.HasFlag(protocol.FlagACK) {
		t.Fatal("expected ACK still set")
	}
}

func TestPacketTooShort(t *testing.T) {
	t.Parallel()
	_, err := protocol.Unmarshal(nil)
	if err == nil {
		t.Fatal("expected error on nil")
	}
	_, err = protocol.Unmarshal([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error on short data")
	}
}

func TestPacketTruncatedPayload(t *testing.T) {
	t.Parallel()
	p := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		Payload:  []byte("test payload"),
	}
	data, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Truncate: keep header but chop off payload
	_, err = protocol.Unmarshal(data[:protocol.PacketHeaderSize()])
	if err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestPacketPayloadTooLarge(t *testing.T) {
	t.Parallel()
	p := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		Payload:  make([]byte, 0x10000), // 65536 = too large
	}
	_, err := p.Marshal()
	if err == nil {
		t.Fatal("expected payload too large error")
	}
}

func TestPacketHeaderSizeFunc(t *testing.T) {
	t.Parallel()
	if protocol.PacketHeaderSize() != 34 {
		t.Fatalf("PacketHeaderSize() = %d, want 34", protocol.PacketHeaderSize())
	}
}

func TestPacketProtocolTypes(t *testing.T) {
	t.Parallel()
	for _, proto := range []uint8{protocol.ProtoStream, protocol.ProtoDatagram, protocol.ProtoControl} {
		p := &protocol.Packet{
			Version:  protocol.Version,
			Protocol: proto,
			Src:      protocol.Addr{Network: 0, Node: 1},
			Dst:      protocol.Addr{Network: 0, Node: 2},
		}
		data, err := p.Marshal()
		if err != nil {
			t.Fatalf("proto 0x%02X: %v", proto, err)
		}
		got, err := protocol.Unmarshal(data)
		if err != nil {
			t.Fatalf("proto 0x%02X unmarshal: %v", proto, err)
		}
		if got.Protocol != proto {
			t.Errorf("protocol = 0x%02X, want 0x%02X", got.Protocol, proto)
		}
	}
}

func TestPacketBigEndianWireOrder(t *testing.T) {
	t.Parallel()
	p := &protocol.Packet{
		Version: protocol.Version,
		Flags:   protocol.FlagSYN,
		Src:     protocol.Addr{Network: 0x0102, Node: 0x03040506},
		Dst:     protocol.Addr{Network: 0x0708, Node: 0x090A0B0C},
		SrcPort: 0x0D0E,
		DstPort: 0x0F10,
		Seq:     0x11121314,
		Ack:     0x15161718,
		Window:  0x191A,
	}
	data, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(data[4:6]) != 0x0102 {
		t.Error("src network not big-endian")
	}
	if binary.BigEndian.Uint32(data[20:24]) != 0x11121314 {
		t.Error("seq not big-endian")
	}
}

func TestPacketUnmarshalPreservesOriginal(t *testing.T) {
	t.Parallel()
	p := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: 1},
		Dst:      protocol.Addr{Network: 0, Node: 2},
		Payload:  []byte("original"),
	}
	data, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := protocol.Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	// Modify data after unmarshal
	data[protocol.PacketHeaderSize()] = 'X'
	if got.Payload[0] == 'X' {
		t.Fatal("Unmarshal aliased payload instead of copying")
	}
}

func TestWellKnownPorts(t *testing.T) {
	t.Parallel()
	if protocol.PortEcho != 7 {
		t.Errorf("PortEcho = %d, want 7", protocol.PortEcho)
	}
	if protocol.PortHTTP != 80 {
		t.Errorf("PortHTTP = %d, want 80", protocol.PortHTTP)
	}
	if protocol.PortSecure != 443 {
		t.Errorf("PortSecure = %d, want 443", protocol.PortSecure)
	}
	if protocol.PortNameserver != 53 {
		t.Errorf("PortNameserver = %d, want 53", protocol.PortNameserver)
	}
}

func TestTunnelMagicBytes(t *testing.T) {
	t.Parallel()
	if string(protocol.TunnelMagic[:]) != "PILT" {
		t.Errorf("TunnelMagic = %q, want PILT", string(protocol.TunnelMagic[:]))
	}
	if string(protocol.TunnelMagicSecure[:]) != "PILS" {
		t.Errorf("TunnelMagicSecure = %q, want PILS", string(protocol.TunnelMagicSecure[:]))
	}
	if string(protocol.TunnelMagicKeyEx[:]) != "PILK" {
		t.Errorf("TunnelMagicKeyEx = %q, want PILK", string(protocol.TunnelMagicKeyEx[:]))
	}
	if string(protocol.TunnelMagicAuthEx[:]) != "PILA" {
		t.Errorf("TunnelMagicAuthEx = %q, want PILA", string(protocol.TunnelMagicAuthEx[:]))
	}
}

func TestPortRanges(t *testing.T) {
	t.Parallel()
	if protocol.PortReservedMax != 1023 {
		t.Errorf("PortReservedMax = %d", protocol.PortReservedMax)
	}
	if protocol.PortEphemeralMin != 49152 {
		t.Errorf("PortEphemeralMin = %d", protocol.PortEphemeralMin)
	}
	if protocol.PortEphemeralMax != 65535 {
		t.Errorf("PortEphemeralMax = %d", protocol.PortEphemeralMax)
	}
	if protocol.PortEphemeralMin <= protocol.PortRegisteredMax {
		t.Error("ephemeral range overlaps registered range")
	}
}
