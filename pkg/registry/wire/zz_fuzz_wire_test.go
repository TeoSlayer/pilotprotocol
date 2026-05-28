// SPDX-License-Identifier: AGPL-3.0-or-later

package wire_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// FuzzReadFrame exercises the binary frame reader.
// Wire format: [4B length][1B type][payload]. The length field is
// length-prefixed; a malicious or buggy peer could send a 4-byte header
// that claims gigabytes — the MaxMessageSize cap should keep it bounded,
// but fuzzing confirms no panic / OOM regression slips in.
func FuzzReadFrame(f *testing.F) {
	// Seed: valid empty-payload JSON frame.
	{
		var buf bytes.Buffer
		wire.WriteFrame(&buf, wire.MsgJSON, []byte("{}"))
		f.Add(buf.Bytes())
	}
	// Seed: valid heartbeat req.
	{
		var buf bytes.Buffer
		wire.WriteFrame(&buf, wire.MsgHeartbeat, wire.EncodeHeartbeatReq(42, make([]byte, 64)))
		f.Add(buf.Bytes())
	}
	// Seed: lookup req.
	{
		var buf bytes.Buffer
		wire.WriteFrame(&buf, wire.MsgLookup, wire.EncodeLookupReq(0xDEADBEEF))
		f.Add(buf.Bytes())
	}
	// Adversarial: huge length field, no body.
	{
		var hdr [5]byte
		binary.BigEndian.PutUint32(hdr[:4], 0xFFFFFFFF)
		hdr[4] = wire.MsgJSON
		f.Add(hdr[:])
	}
	// Adversarial: length=0 (below the "must include type byte" minimum).
	{
		var hdr [5]byte
		binary.BigEndian.PutUint32(hdr[:4], 0)
		hdr[4] = wire.MsgJSON
		f.Add(hdr[:])
	}
	f.Add([]byte{})
	f.Add(make([]byte, 4))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		r := bytes.NewReader(data)
		_, _, _ = wire.ReadFrame(r)
	})
}

// FuzzDecodeLookupResp targets the wire-controlled allocation path
// flagged in PILOT-131. The decoder pulls counts (network count, tag
// count, length-prefixed fields) directly from the input — a 16-bit
// network count or 8-bit tag count drives `make([]uint16, n)` /
// `make([]string, n)`. Truncated inputs must surface as errors, not
// panics, and not unbounded allocations.
func FuzzDecodeLookupResp(f *testing.F) {
	f.Add(wire.EncodeLookupResp(1, false, false, nil, nil, "", nil, "", ""))
	f.Add(wire.EncodeLookupResp(0xDEADBEEF, true, true,
		[]uint16{1, 2, 3}, []byte("pubkey"), "host", []string{"a", "b"},
		"1.2.3.4:5", "extid"))
	f.Add(wire.EncodeLookupResp(7, true, false,
		[]uint16{42}, bytes.Repeat([]byte{0x55}, 255), "h", []string{"tag"},
		"", ""))

	// Adversarial: header claims many networks but no body follows.
	{
		buf := make([]byte, 11)
		binary.BigEndian.PutUint32(buf[:4], 1)
		buf[4] = 0
		// reserved (4) zero
		binary.BigEndian.PutUint16(buf[9:11], 0xFFFF) // claim 65535 networks
		f.Add(buf)
	}
	// Adversarial: pubkey_len > remaining bytes.
	{
		buf := make([]byte, 12)
		binary.BigEndian.PutUint32(buf[:4], 1)
		// reserved + netcount = 0
		buf[11] = 0xFF // pubkey_len = 255
		f.Add(buf)
	}
	// Minimum-size buffer.
	f.Add(make([]byte, 11))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		_, _ = wire.DecodeLookupResp(data)
	})
}

// FuzzDecodeResolveResp covers the resolve response decoder which has
// the same wire-controlled allocation shape (count + length-prefixed
// LAN addrs).
func FuzzDecodeResolveResp(f *testing.F) {
	f.Add(wire.EncodeResolveResp(1, "1.2.3.4:5", nil, 0))
	f.Add(wire.EncodeResolveResp(2, "10.0.0.1:9000",
		[]string{"192.168.1.1", "10.0.0.5"}, 30))
	f.Add(wire.EncodeResolveResp(3, "", nil, -1))
	f.Add(make([]byte, 12))
	f.Add([]byte{})

	// Adversarial: LAN count overflow.
	{
		buf := make([]byte, 8)
		binary.BigEndian.PutUint32(buf[:4], 1)
		binary.BigEndian.PutUint16(buf[4:6], 0)      // addr_len = 0
		binary.BigEndian.PutUint16(buf[6:8], 0xFFFF) // 65535 LAN addrs
		f.Add(buf)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		_, _ = wire.DecodeResolveResp(data)
	})
}

// FuzzDecodeHeartbeatReq / Resp / LookupReq / Error are simple
// fixed-shape decoders — fuzz them anyway since they're entry points.
func FuzzDecodeHeartbeatReq(f *testing.F) {
	f.Add(wire.EncodeHeartbeatReq(1, make([]byte, 64)))
	f.Add(wire.EncodeHeartbeatReq(0xFFFFFFFF, bytes.Repeat([]byte{0xAA}, 64)))
	f.Add([]byte{})
	f.Add(make([]byte, 67)) // one byte short

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		_, _ = wire.DecodeHeartbeatReq(data)
	})
}

func FuzzDecodeError(f *testing.F) {
	f.Add(wire.EncodeError("oh no"))
	f.Add(wire.EncodeError(""))
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		_ = wire.DecodeError(data)
	})
}

// FuzzReadMessage exercises the JSON length-prefixed message reader.
// The 4-byte length is wire-controlled; the MaxMessageSize check is the
// only guard against `make([]byte, hugeLength)`. Verify no panic and no
// OOM-by-allocation regression.
func FuzzReadMessage(f *testing.F) {
	// Seed: valid 2-byte JSON `{}`.
	{
		var buf bytes.Buffer
		_ = wire.WriteMessage(&buf, map[string]interface{}{})
		f.Add(buf.Bytes())
	}
	{
		var buf bytes.Buffer
		_ = wire.WriteMessage(&buf, map[string]interface{}{
			"op": "lookup", "node_id": float64(42),
		})
		f.Add(buf.Bytes())
	}
	// Adversarial: header claims big payload.
	{
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 0xFFFFFFFF)
		f.Add(hdr)
	}
	// Length declares 4GB but no body follows.
	{
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, 0x7FFFFFFF)
		f.Add(hdr)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 3))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		r := bytes.NewReader(data)
		_, _ = wire.ReadMessage(r)
	})
}
