package protocol

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

const AddrSize = 6 // 48 bits: 2 bytes network + 4 bytes node

// Addr is a 48-bit Pilot Protocol virtual address.
// Layout: [16-bit Network ID][32-bit Node ID]
// Text format: N:NNNN.HHHH.LLLL
//
//	N    = network ID in decimal
//	NNNN = network ID in hex (redundant, for readability)
//	HHHH = node ID high 16 bits in hex
//	LLLL = node ID low 16 bits in hex
type Addr struct {
	Network uint16
	Node    uint32
}

var (
	AddrZero       = Addr{0, 0}
	AddrRegistry   = Addr{0, 1}
	AddrBeacon     = Addr{0, 2}
	AddrNameserver = Addr{0, 3}
)

// BroadcastAddr returns the broadcast address for a given network.
func BroadcastAddr(network uint16) Addr {
	return Addr{Network: network, Node: 0xFFFFFFFF}
}

func (a Addr) IsZero() bool      { return a.Network == 0 && a.Node == 0 }
func (a Addr) IsBroadcast() bool { return a.Node == 0xFFFFFFFF }

// Marshal writes the address as 6 bytes (big-endian).
func (a Addr) Marshal() []byte {
	b := make([]byte, AddrSize)
	a.MarshalTo(b, 0)
	return b
}

// MarshalTo writes the address into buf at the given offset.
func (a Addr) MarshalTo(buf []byte, offset int) {
	binary.BigEndian.PutUint16(buf[offset:], a.Network)
	binary.BigEndian.PutUint32(buf[offset+2:], a.Node)
}

// UnmarshalAddr reads a 6-byte address from buf.
func UnmarshalAddr(buf []byte) Addr {
	return Addr{
		Network: binary.BigEndian.Uint16(buf[0:2]),
		Node:    binary.BigEndian.Uint32(buf[2:6]),
	}
}

// String returns the text representation: N:NNNN.HHHH.LLLL
func (a Addr) String() string {
	return fmt.Sprintf("%d:%04X.%04X.%04X", a.Network, a.Network, (a.Node>>16)&0xFFFF, a.Node&0xFFFF)
}

// ParseAddr parses "0:0000.0000.0001" or "1:00A3.F291.0004" into an Addr.
func ParseAddr(s string) (Addr, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return AddrZero, fmt.Errorf("invalid address: %q (expected N:XXXX.YYYY.YYYY)", s)
	}

	networkDec, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return AddrZero, fmt.Errorf("invalid network ID: %q: %w", parts[0], err)
	}

	hexGroups := strings.Split(parts[1], ".")
	if len(hexGroups) != 3 {
		return AddrZero, fmt.Errorf("invalid address: %q (expected 3 dot-separated hex groups)", parts[1])
	}
	for _, h := range hexGroups {
		if len(h) != 4 {
			return AddrZero, fmt.Errorf("invalid hex group: %q (expected 4 digits)", h)
		}
	}

	netHex, err := strconv.ParseUint(hexGroups[0], 16, 16)
	if err != nil {
		return AddrZero, fmt.Errorf("invalid hex group: %q: %w", hexGroups[0], err)
	}
	if netHex != networkDec {
		return AddrZero, fmt.Errorf("network mismatch: decimal %d != hex 0x%04X", networkDec, netHex)
	}

	nodeHigh, err := strconv.ParseUint(hexGroups[1], 16, 16)
	if err != nil {
		return AddrZero, fmt.Errorf("invalid hex group: %q: %w", hexGroups[1], err)
	}
	nodeLow, err := strconv.ParseUint(hexGroups[2], 16, 16)
	if err != nil {
		return AddrZero, fmt.Errorf("invalid hex group: %q: %w", hexGroups[2], err)
	}

	return Addr{
		Network: uint16(networkDec),
		Node:    uint32(nodeHigh)<<16 | uint32(nodeLow),
	}, nil
}

// SocketAddr is a full endpoint: virtual address + port.
type SocketAddr struct {
	Addr Addr
	Port uint16
}

func (sa SocketAddr) String() string {
	return fmt.Sprintf("%s:%d", sa.Addr.String(), sa.Port)
}

// ParseSocketAddr parses "N:XXXX.YYYY.YYYY:PORT".
func ParseSocketAddr(s string) (SocketAddr, error) {
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return SocketAddr{}, fmt.Errorf("invalid socket address: %q (no port)", s)
	}

	addr, err := ParseAddr(s[:lastColon])
	if err != nil {
		return SocketAddr{}, err
	}

	port, err := strconv.ParseUint(s[lastColon+1:], 10, 16)
	if err != nil {
		return SocketAddr{}, fmt.Errorf("invalid port: %q: %w", s[lastColon+1:], err)
	}

	return SocketAddr{Addr: addr, Port: uint16(port)}, nil
}
