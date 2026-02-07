package protocol

// Protocol version
const Version uint8 = 1

// Flags (4 bits, stored in lower nibble of first byte alongside version)
const (
	FlagSYN uint8 = 0x1
	FlagACK uint8 = 0x2
	FlagFIN uint8 = 0x4
	FlagRST uint8 = 0x8
)

// Protocol types
const (
	ProtoStream   uint8 = 0x01 // Reliable, ordered (TCP-like)
	ProtoDatagram uint8 = 0x02 // Unreliable, unordered (UDP-like)
	ProtoControl  uint8 = 0x03 // Internal control
)

// Well-known ports
const (
	PortPing         uint16 = 0
	PortControl      uint16 = 1
	PortEcho         uint16 = 7
	PortNameserver   uint16 = 53
	PortHTTP         uint16 = 80
	PortSecure       uint16 = 443
	PortStdIO        uint16 = 1000
	PortDataExchange uint16 = 1001
	PortEventStream  uint16 = 1002
)

// Port ranges
const (
	PortReservedMax  uint16 = 1023
	PortRegisteredMax uint16 = 49151
	PortEphemeralMin uint16 = 49152
	PortEphemeralMax uint16 = 65535
)

// Tunnel magic bytes: "PILT" (0x50494C54)
var TunnelMagic = [4]byte{0x50, 0x49, 0x4C, 0x54}

// Tunnel magic bytes for encrypted packets: "PILS" (0x50494C53)
var TunnelMagicSecure = [4]byte{0x50, 0x49, 0x4C, 0x53}

// Tunnel magic bytes for key exchange: "PILK" (0x50494C4B)
var TunnelMagicKeyEx = [4]byte{0x50, 0x49, 0x4C, 0x4B}

// Tunnel magic bytes for authenticated key exchange: "PILA" (0x50494C41)
var TunnelMagicAuthEx = [4]byte{0x50, 0x49, 0x4C, 0x41}

// Well-known port for handshake requests
const PortHandshake uint16 = 444
