package protocol

import (
	"encoding/binary"
	"fmt"
)

// Wire layout (34 bytes):
//
//	Byte  0:     [Version:4][Flags:4]
//	Byte  1:     Protocol
//	Byte  2-3:   Payload Length
//	Byte  4-9:   Source Address (6 bytes)
//	Byte  10-15: Destination Address (6 bytes)
//	Byte  16-17: Source Port
//	Byte  18-19: Destination Port
//	Byte  20-23: Sequence Number
//	Byte  24-27: Acknowledgment Number
//	Byte  28-29: Window (receive window in segments, 0 = no flow control)
//	Byte  30-33: Checksum (CRC32)
const packetHeaderSize = 34

type Packet struct {
	Version  uint8
	Flags    uint8
	Protocol uint8

	Src     Addr
	Dst     Addr
	SrcPort uint16
	DstPort uint16

	Seq    uint32
	Ack    uint32
	Window uint16 // advertised receive window (in segments; 0 = no limit)

	Payload []byte
}

func (p *Packet) HasFlag(f uint8) bool { return p.Flags&f != 0 }
func (p *Packet) SetFlag(f uint8)      { p.Flags |= f }
func (p *Packet) ClearFlag(f uint8)    { p.Flags &^= f }

// Marshal serializes the packet to wire format with checksum.
func (p *Packet) Marshal() ([]byte, error) {
	payloadLen := len(p.Payload)
	if payloadLen > 0xFFFF {
		return nil, fmt.Errorf("payload too large: %d bytes (max 65535)", payloadLen)
	}

	totalLen := packetHeaderSize + payloadLen // safe: payloadLen ≤ 0xFFFF (checked above)
	buf := make([]byte, totalLen)

	buf[0] = (p.Version << 4) | (p.Flags & 0x0F)
	buf[1] = p.Protocol
	binary.BigEndian.PutUint16(buf[2:4], uint16(payloadLen))
	p.Src.MarshalTo(buf, 4)
	p.Dst.MarshalTo(buf, 10)
	binary.BigEndian.PutUint16(buf[16:18], p.SrcPort)
	binary.BigEndian.PutUint16(buf[18:20], p.DstPort)
	binary.BigEndian.PutUint32(buf[20:24], p.Seq)
	binary.BigEndian.PutUint32(buf[24:28], p.Ack)
	binary.BigEndian.PutUint16(buf[28:30], p.Window)

	if payloadLen > 0 {
		copy(buf[packetHeaderSize:], p.Payload)
	}

	// Checksum: CRC32 over header (with checksum field zeroed) + payload.
	// Field is already zero from make().
	binary.BigEndian.PutUint32(buf[30:34], Checksum(buf))

	return buf, nil
}

// Unmarshal deserializes a packet from wire bytes.
func Unmarshal(data []byte) (*Packet, error) {
	if len(data) < packetHeaderSize {
		return nil, fmt.Errorf("packet too short: %d bytes (min %d)", len(data), packetHeaderSize)
	}

	payloadLen := binary.BigEndian.Uint16(data[2:4])
	total := packetHeaderSize + int(payloadLen)
	if len(data) < total {
		return nil, fmt.Errorf("packet truncated: have %d bytes, need %d", len(data), total)
	}

	// Verify checksum before parsing.
	wireChecksum := binary.BigEndian.Uint32(data[30:34])
	binary.BigEndian.PutUint32(data[30:34], 0) // zero for computation
	computed := Checksum(data[:total])
	binary.BigEndian.PutUint32(data[30:34], wireChecksum) // restore

	if computed != wireChecksum {
		return nil, ErrChecksumMismatch
	}

	p := &Packet{
		Version:  (data[0] >> 4) & 0x0F,
		Flags:    data[0] & 0x0F,
		Protocol: data[1],
		Src:      UnmarshalAddr(data[4:10]),
		Dst:      UnmarshalAddr(data[10:16]),
		SrcPort:  binary.BigEndian.Uint16(data[16:18]),
		DstPort:  binary.BigEndian.Uint16(data[18:20]),
		Seq:      binary.BigEndian.Uint32(data[20:24]),
		Ack:      binary.BigEndian.Uint32(data[24:28]),
		Window:   binary.BigEndian.Uint16(data[28:30]),
	}

	if payloadLen > 0 {
		p.Payload = make([]byte, payloadLen)
		copy(p.Payload, data[packetHeaderSize:total])
	}

	return p, nil
}

func PacketHeaderSize() int { return packetHeaderSize }
