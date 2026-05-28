// SPDX-License-Identifier: AGPL-3.0-or-later

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Addr
// ---------------------------------------------------------------------------

func TestAddrIsZero(t *testing.T) {
	t.Parallel()
	if !ZeroAddr().IsZero() {
		t.Fatal("ZeroAddr().IsZero() should be true")
	}
	if AddrRegistry.IsZero() {
		t.Fatal("AddrRegistry should not be zero")
	}
	if (Addr{Network: 1}).IsZero() {
		t.Fatal("non-zero network should not be zero")
	}
	if (Addr{Node: 1}).IsZero() {
		t.Fatal("non-zero node should not be zero")
	}
}

func TestAddrIsBroadcast(t *testing.T) {
	t.Parallel()
	b := BroadcastAddr(5)
	if !b.IsBroadcast() {
		t.Fatalf("BroadcastAddr(5).IsBroadcast() = false")
	}
	if b.Network != 5 {
		t.Fatalf("BroadcastAddr network = %d, want 5", b.Network)
	}
	if (Addr{Node: 0xFFFFFFFE}).IsBroadcast() {
		t.Fatal("non-broadcast node should not be broadcast")
	}
}

func TestAddrMarshalUnmarshalRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []Addr{
		ZeroAddr(),
		AddrRegistry,
		{Network: 0xABCD, Node: 0x12345678},
		{Network: 0xFFFF, Node: 0xFFFFFFFF},
	}
	for _, in := range cases {
		buf := in.Marshal()
		if len(buf) != AddrSize {
			t.Fatalf("Marshal len = %d, want %d", len(buf), AddrSize)
		}
		out := UnmarshalAddr(buf)
		if out != in {
			t.Fatalf("round-trip: got %+v, want %+v", out, in)
		}
	}
}

func TestAddrMarshalToOffset(t *testing.T) {
	t.Parallel()
	a := Addr{Network: 0xCAFE, Node: 0xDEADBEEF}
	buf := make([]byte, 20)
	a.MarshalTo(buf, 8)
	out := UnmarshalAddr(buf[8:14])
	if out != a {
		t.Fatalf("MarshalTo offset round-trip: got %+v, want %+v", out, a)
	}
	// Bytes outside the 6-byte window must remain zero
	for i := 0; i < 8; i++ {
		if buf[i] != 0 {
			t.Errorf("byte %d not zero before offset: 0x%02x", i, buf[i])
		}
	}
	for i := 14; i < 20; i++ {
		if buf[i] != 0 {
			t.Errorf("byte %d not zero after offset: 0x%02x", i, buf[i])
		}
	}
}

func TestUnmarshalAddrShortBuffer(t *testing.T) {
	t.Parallel()
	// PILOT-133: UnmarshalAddr must not panic on short buffers.
	// It should return a zero address instead of indexing out of bounds.

	// 0 bytes
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("UnmarshalAddr panicked on 0-byte buffer: %v", r)
			}
		}()
		a := UnmarshalAddr([]byte{})
		if !a.IsZero() {
			t.Errorf("expected zero addr for empty buffer, got %+v", a)
		}
	}()

	// 3 bytes
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("UnmarshalAddr panicked on 3-byte buffer: %v", r)
			}
		}()
		a := UnmarshalAddr([]byte{0x00, 0x01, 0x02})
		if !a.IsZero() {
			t.Errorf("expected zero addr for short buffer, got %+v", a)
		}
	}()

	// 5 bytes (one short)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("UnmarshalAddr panicked on 5-byte buffer: %v", r)
			}
		}()
		a := UnmarshalAddr([]byte{0x00, 0x01, 0xDE, 0xAD, 0xBE})
		if !a.IsZero() {
			t.Errorf("expected zero addr for 5-byte buffer, got %+v", a)
		}
	}()

	// 6 bytes (valid, should work normally)
	a := UnmarshalAddr([]byte{0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF})
	want := Addr{Network: 0x0001, Node: 0xDEADBEEF}
	if a != want {
		t.Errorf("valid 6-byte buffer: got %+v, want %+v", a, want)
	}
}

func TestAddrStringFormat(t *testing.T) {
	t.Parallel()
	a := Addr{Network: 0x00A3, Node: 0xF2910004}
	got := a.String()
	want := "163:00A3.F291.0004"
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestParseAddrValid(t *testing.T) {
	t.Parallel()
	in := "163:00A3.F291.0004"
	a, err := ParseAddr(in)
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	if a.Network != 0x00A3 || a.Node != 0xF2910004 {
		t.Fatalf("parsed addr wrong: %+v", a)
	}
	// Round-trip via String must equal input
	if a.String() != in {
		t.Fatalf("round-trip: %q != %q", a.String(), in)
	}
}

func TestParseAddrErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantSub string
	}{
		{"no-colon", "expected N:XXXX"},
		{"abc:0000.0000.0000", "invalid network ID"},
		{"1:0000.0000", "expected 3 dot-separated"},
		{"1:000.0000.0000", "expected 4 digits"},
		{"1:GGGG.0000.0000", "invalid hex group"},
		{"1:0001.GGGG.0000", "invalid hex group"}, // network matches so we reach the high-group check
		{"1:0001.0000.GGGG", "invalid hex group"}, // network matches so we reach the low-group check
		{"1:0002.0000.0000", "network mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			_, err := ParseAddr(tc.in)
			if err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q missing substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SocketAddr
// ---------------------------------------------------------------------------

func TestSocketAddrStringAndParse(t *testing.T) {
	t.Parallel()
	in := SocketAddr{Addr: Addr{Network: 1, Node: 0x00010001}, Port: 8080}
	str := in.String()
	if str != "1:0001.0001.0001:8080" {
		t.Fatalf("String() = %q", str)
	}
	out, err := ParseSocketAddr(str)
	if err != nil {
		t.Fatalf("ParseSocketAddr: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip: got %+v, want %+v", out, in)
	}
}

func TestParseSocketAddrErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		wantSub string
	}{
		{"noport", "no port"},
		{"bad-addr:80", "invalid address"},
		{"1:0001.0001.0001:notanumber", "invalid port"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			_, err := ParseSocketAddr(tc.in)
			if err == nil {
				t.Fatalf("expected error for %q", tc.in)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q missing substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Packet flags + Marshal/Unmarshal
// ---------------------------------------------------------------------------

func TestPacketFlagOps(t *testing.T) {
	t.Parallel()
	p := &Packet{}
	if p.HasFlag(FlagSYN) {
		t.Fatal("fresh packet should have no flags")
	}
	p.SetFlag(FlagSYN)
	p.SetFlag(FlagACK)
	if !p.HasFlag(FlagSYN) || !p.HasFlag(FlagACK) {
		t.Fatalf("set flags not detected: flags=0x%x", p.Flags)
	}
	if p.HasFlag(FlagFIN) {
		t.Fatal("FIN should not be set")
	}
	p.ClearFlag(FlagSYN)
	if p.HasFlag(FlagSYN) {
		t.Fatal("SYN should be cleared")
	}
	if !p.HasFlag(FlagACK) {
		t.Fatal("ACK should still be set")
	}
}

func TestPacketHeaderSize(t *testing.T) {
	t.Parallel()
	if PacketHeaderSize() != 34 {
		t.Fatalf("PacketHeaderSize() = %d, want 34", PacketHeaderSize())
	}
}

func TestPacketMarshalUnmarshalRoundTrip(t *testing.T) {
	t.Parallel()
	in := &Packet{
		Version:  Version,
		Flags:    FlagACK | FlagSYN,
		Protocol: ProtoStream,
		Src:      Addr{Network: 1, Node: 0x12345678},
		Dst:      Addr{Network: 2, Node: 0xABCDEF01},
		SrcPort:  4040,
		DstPort:  PortHTTP,
		Seq:      1234,
		Ack:      5678,
		Window:   64,
		Payload:  []byte("hello world"),
	}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(buf) != 34+len(in.Payload) {
		t.Fatalf("buf len = %d, want %d", len(buf), 34+len(in.Payload))
	}
	out, err := Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Version != in.Version || out.Flags != in.Flags || out.Protocol != in.Protocol {
		t.Fatalf("header mismatch: got %+v", out)
	}
	if out.Src != in.Src || out.Dst != in.Dst {
		t.Fatalf("addr mismatch: got src=%v dst=%v", out.Src, out.Dst)
	}
	if out.SrcPort != in.SrcPort || out.DstPort != in.DstPort {
		t.Fatalf("port mismatch: got src=%d dst=%d", out.SrcPort, out.DstPort)
	}
	if out.Seq != in.Seq || out.Ack != in.Ack || out.Window != in.Window {
		t.Fatalf("seq/ack/window mismatch: got seq=%d ack=%d window=%d", out.Seq, out.Ack, out.Window)
	}
	if !bytes.Equal(out.Payload, in.Payload) {
		t.Fatalf("payload mismatch: got %q", out.Payload)
	}
}

func TestPacketMarshalEmptyPayload(t *testing.T) {
	t.Parallel()
	in := &Packet{Version: Version, Protocol: ProtoControl}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(buf) != 34 {
		t.Fatalf("len = %d, want 34", len(buf))
	}
	out, err := Unmarshal(buf)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(out.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(out.Payload))
	}
}

func TestPacketMarshalPayloadTooLarge(t *testing.T) {
	t.Parallel()
	in := &Packet{Version: Version, Payload: make([]byte, 0x10000)} // 65536, exceeds 0xFFFF
	_, err := in.Marshal()
	if err == nil {
		t.Fatal("expected payload-too-large error")
	}
	if !strings.Contains(err.Error(), "payload too large") {
		t.Fatalf("error %q missing substring", err)
	}
}

func TestUnmarshalTooShort(t *testing.T) {
	t.Parallel()
	_, err := Unmarshal(make([]byte, 33))
	if err == nil {
		t.Fatal("expected too-short error")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("error %q missing substring", err)
	}
}

func TestUnmarshalTruncatedPayload(t *testing.T) {
	t.Parallel()
	// Build a header claiming 100-byte payload but send only the header.
	buf := make([]byte, 34)
	buf[0] = Version << 4
	binary.BigEndian.PutUint16(buf[2:4], 100)
	_, err := Unmarshal(buf)
	if err == nil {
		t.Fatal("expected truncated error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error %q missing 'truncated'", err)
	}
}

func TestUnmarshalChecksumMismatch(t *testing.T) {
	t.Parallel()
	in := &Packet{Version: Version, Protocol: ProtoStream, Payload: []byte("abc")}
	buf, _ := in.Marshal()
	// Corrupt one byte in the payload
	buf[34] ^= 0xFF
	_, err := Unmarshal(buf)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestUnmarshalUnsupportedVersion(t *testing.T) {
	t.Parallel()
	in := &Packet{Version: Version, Payload: []byte("x")}
	buf, _ := in.Marshal()
	// Flip the version nibble to a different value, then re-checksum so we
	// hit the version check rather than the checksum check.
	buf[0] = (0xA << 4) | (buf[0] & 0x0F) // version = 0xA
	binary.BigEndian.PutUint32(buf[30:34], 0)
	cs := Checksum(buf)
	binary.BigEndian.PutUint32(buf[30:34], cs)
	_, err := Unmarshal(buf)
	if err == nil {
		t.Fatal("expected unsupported version error")
	}
	if !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Fatalf("error %q missing substring", err)
	}
}

func TestUnmarshalRestoresChecksumBytes(t *testing.T) {
	t.Parallel()
	// Verify Unmarshal does not permanently mutate the caller's buffer
	// (it temporarily zeroes the checksum field for computation, then restores).
	in := &Packet{Version: Version, Protocol: ProtoStream, Payload: []byte("xyz")}
	buf, _ := in.Marshal()
	original := append([]byte(nil), buf...)
	if _, err := Unmarshal(buf); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(buf, original) {
		t.Fatalf("Unmarshal mutated caller buffer: original checksum bytes %x, current %x",
			original[30:34], buf[30:34])
	}
}

// ---------------------------------------------------------------------------
// Checksum
// ---------------------------------------------------------------------------

func TestChecksumDeterministic(t *testing.T) {
	t.Parallel()
	data := []byte("the quick brown fox")
	c1 := Checksum(data)
	c2 := Checksum(data)
	if c1 != c2 {
		t.Fatalf("Checksum non-deterministic: %d != %d", c1, c2)
	}
}

func TestChecksumDiffersOnSingleBitFlip(t *testing.T) {
	t.Parallel()
	a := []byte("payload")
	b := append([]byte(nil), a...)
	b[0] ^= 0x01
	if Checksum(a) == Checksum(b) {
		t.Fatal("checksum did not detect 1-bit flip")
	}
}
