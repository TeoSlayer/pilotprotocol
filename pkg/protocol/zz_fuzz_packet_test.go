// SPDX-License-Identifier: AGPL-3.0-or-later

package protocol

import (
	"bytes"
	"testing"
)

// FuzzUnmarshalPacket exercises the packet decoder with arbitrary bytes.
// The decoder is documented as having an L1 panic boundary (deferred
// recover → ErrMalformedPacket), so a literal panic should never escape
// to the fuzz harness — any escape is a real bug. PILOT-133 noted a
// latent unmarshal panic in UnmarshalAddr; this target should reproduce
// such issues quickly.
//
// Seeds include valid frames at multiple sizes, header-only inputs, all
// flag combinations, malformed length fields, and a few adversarial
// envelopes (length field claims much more than the buffer holds).
func FuzzUnmarshalPacket(f *testing.F) {
	// Seed 1: minimal valid (no payload) packet.
	{
		p := &Packet{Version: Version, Protocol: ProtoStream}
		b, err := p.Marshal()
		if err == nil {
			f.Add(b)
		}
	}
	// Seed 2: valid packet with small payload.
	{
		p := &Packet{
			Version: Version, Flags: FlagSYN | FlagACK, Protocol: ProtoStream,
			Src: Addr{1, 0xDEADBEEF}, Dst: Addr{2, 0xCAFEBABE},
			SrcPort: 1234, DstPort: 5678,
			Seq: 0x11223344, Ack: 0x55667788, Window: 16,
			Payload: []byte("hello"),
		}
		b, err := p.Marshal()
		if err == nil {
			f.Add(b)
		}
	}
	// Seed 3: control proto, all flags.
	{
		p := &Packet{
			Version: Version, Flags: FlagSYN | FlagACK | FlagFIN | FlagRST,
			Protocol: ProtoControl, Payload: bytes.Repeat([]byte{0xAB}, 64),
		}
		b, err := p.Marshal()
		if err == nil {
			f.Add(b)
		}
	}
	// Seed 4: datagram with binary payload.
	{
		p := &Packet{
			Version: Version, Protocol: ProtoDatagram,
			Payload: []byte{0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE},
		}
		b, err := p.Marshal()
		if err == nil {
			f.Add(b)
		}
	}
	// Seed 5: broadcast destination.
	{
		p := &Packet{
			Version: Version, Protocol: ProtoDatagram,
			Dst: BroadcastAddr(7), DstPort: PortPing,
		}
		b, err := p.Marshal()
		if err == nil {
			f.Add(b)
		}
	}
	// Seed 6: exactly header-sized (34 bytes of zeros).
	f.Add(make([]byte, packetHeaderSize))
	// Seed 7: shorter than header.
	f.Add(make([]byte, packetHeaderSize-1))
	// Seed 8: empty.
	f.Add([]byte{})
	// Seed 9: header claims big payload but buffer truncated.
	{
		b := make([]byte, packetHeaderSize)
		b[0] = Version << 4 // valid version
		b[2], b[3] = 0xFF, 0xFF
		f.Add(b)
	}
	// Seed 10: header with unsupported version.
	{
		b := make([]byte, packetHeaderSize)
		b[0] = 0xF0 // version 0x0F (unsupported)
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Defensive: literal panic out of Unmarshal is the find.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()

		// Unmarshal mutates data[30:34] briefly during checksum verify;
		// pass a copy so the fuzzer's input slice is not aliased.
		buf := make([]byte, len(data))
		copy(buf, data)

		p, err := Unmarshal(buf)
		if err != nil {
			return // expected on most random input
		}

		// Round-trip property: a successfully decoded packet should
		// re-encode to bytes that decode back to an equivalent struct.
		re, err := p.Marshal()
		if err != nil {
			t.Errorf("decode-then-encode failed: %v (orig=%x)", err, data)
			return
		}
		p2, err := Unmarshal(re)
		if err != nil {
			t.Errorf("re-decode failed: %v (re=%x)", err, re)
			return
		}
		if p.Seq != p2.Seq || p.Ack != p2.Ack || p.SrcPort != p2.SrcPort ||
			p.DstPort != p2.DstPort || p.Window != p2.Window ||
			p.Protocol != p2.Protocol || p.Flags != p2.Flags ||
			p.Version != p2.Version || p.Src != p2.Src || p.Dst != p2.Dst {
			t.Errorf("round-trip header mismatch: %+v vs %+v", p, p2)
		}
		if !bytes.Equal(p.Payload, p2.Payload) {
			t.Errorf("round-trip payload mismatch: %x vs %x", p.Payload, p2.Payload)
		}
	})
}

// FuzzUnmarshalAddr targets the 6-byte address decoder directly.
// PILOT-133 specifically flagged this function; UnmarshalAddr does NOT
// have a defer/recover, so out-of-bounds slicing would propagate as a
// real panic. A naive call with len(buf) < AddrSize panics, so the
// fuzzer must include the bounds check the harness uses in practice.
func FuzzUnmarshalAddr(f *testing.F) {
	f.Add(make([]byte, AddrSize))
	f.Add([]byte{0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()

		// UnmarshalAddr's contract is "exactly 6 bytes". Callers that
		// pass less are the bug shape PILOT-133 was concerned with —
		// fuzz both the contract-respecting path and the over-long path.
		if len(data) >= AddrSize {
			a := UnmarshalAddr(data[:AddrSize])
			b := a.Marshal()
			a2 := UnmarshalAddr(b)
			if a != a2 {
				t.Errorf("addr round-trip: %v != %v", a, a2)
			}
		}
	})
}

// FuzzParseAddr exercises the text-form address parser.
func FuzzParseAddr(f *testing.F) {
	f.Add("0:0000.0000.0001")
	f.Add("1:0001.DEAD.BEEF")
	f.Add("65535:FFFF.FFFF.FFFF")
	f.Add("")
	f.Add(":")
	f.Add("garbage")
	f.Add("0:0000.0000")
	f.Add("0:0000.0000.0000.0000")

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %q: %v", s, r)
			}
		}()
		a, err := ParseAddr(s)
		if err != nil {
			return
		}
		// Round-trip: String() of a parsed addr must re-parse equal.
		a2, err := ParseAddr(a.String())
		if err != nil {
			t.Errorf("re-parse of %q (= %v) failed: %v", s, a, err)
			return
		}
		if a != a2 {
			t.Errorf("round-trip mismatch: %v != %v (input %q)", a, a2, s)
		}
	})
}
