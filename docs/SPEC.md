# Pilot Protocol Wire Specification v0.5

## 1. Addressing

### 1.1 Virtual Address Format

Addresses are 48-bit, split into two fields:

```
[ 16-bit Network ID ][ 32-bit Node ID ]
```

- **Network ID** (16 bits) -- identifies the network/topic. `0x0000` is the global backbone.
- **Node ID** (32 bits) -- identifies the agent. ~4 billion nodes per network.

### 1.2 Text Representation

Format: `N:XXXX.YYYY.YYYY`

- `N` -- network ID in decimal
- Node ID -- three dot-separated groups of 4 hex digits

Examples:
- `0:0000.0000.0001` -- Node 1 on the backbone
- `1:00A3.F291.0004` -- Node on network 1

Socket address includes a port: `1:00A3.F291.0004:1000`

### 1.3 Special Addresses

| Address | Meaning |
|---------|---------|
| `0:0000.0000.0000` | Unspecified / wildcard |
| `0:0000.0000.0001` | Registry |
| `0:0000.0000.0002` | Beacon |
| `0:0000.0000.0003` | Nameserver |
| `X:FFFF.FFFF.FFFF` | Broadcast on network X |

---

## 2. Ports

16-bit virtual ports (0--65535).

### 2.1 Port Ranges

| Range | Purpose |
|-------|---------|
| 0--1023 | Reserved / well-known |
| 1024--49151 | Registered services |
| 49152--65535 | Ephemeral / dynamic |

### 2.2 Well-Known Ports

| Port | Service | Description |
|------|---------|-------------|
| 0 | Ping / heartbeat | Liveness checks |
| 1 | Control channel | Daemon-to-daemon control |
| 7 | Echo | Echo service (testing) |
| 53 | Name resolution | Nameserver queries |
| 80 | Agent HTTP | Web endpoints |
| 443 | Secure channel | X25519 + AES-256-GCM |
| 444 | Trust handshake | Peer trust negotiation |
| 1000 | Standard I/O | Text stream between agents |
| 1001 | Data exchange | Typed frames (text, binary, JSON, file) |
| 1002 | Event stream | Pub/sub with topic filtering |

---

## 3. Packet Format

### 3.1 Header Layout (34 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Ver  | Flags |   Protocol    |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Source Network ID       |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Source Node ID           |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Destination Network ID    |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     Destination Node ID       |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Source Port            |      Destination Port         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Window (segments)       |         Checksum (hi)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Checksum (lo)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Field Definitions

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Version | 0 | 4 bits | Protocol version. Current: `1` |
| Flags | 0 | 4 bits | SYN (0x1), ACK (0x2), FIN (0x4), RST (0x8) |
| Protocol | 1 | 1 byte | Transport type (see 3.3) |
| Payload Length | 2 | 2 bytes | Payload length in bytes (max 65,535) |
| Source Network | 4 | 2 bytes | Source network ID |
| Source Node | 6 | 4 bytes | Source node ID |
| Destination Network | 10 | 2 bytes | Destination network ID |
| Destination Node | 12 | 4 bytes | Destination node ID |
| Source Port | 16 | 2 bytes | Source port |
| Destination Port | 18 | 2 bytes | Destination port |
| Sequence Number | 20 | 4 bytes | Byte offset of this segment |
| Acknowledgment Number | 24 | 4 bytes | Next expected byte from peer |
| Window | 28 | 2 bytes | Advertised receive window in segments. `0` = no limit. |
| Checksum | 30 | 4 bytes | CRC32 over header (with checksum zeroed) + payload |

All fields are big-endian.

### 3.3 Protocol Types

| Value | Name | Description |
|-------|------|-------------|
| 0x01 | Stream | Reliable, ordered delivery (TCP-like) |
| 0x02 | Datagram | Unreliable, unordered (UDP-like) |
| 0x03 | Control | Internal control messages |

### 3.4 Flag Definitions

| Bit | Name | Description |
|-----|------|-------------|
| 0 | SYN | Synchronize -- initiate connection |
| 1 | ACK | Acknowledge -- confirm receipt |
| 2 | FIN | Finish -- close connection |
| 3 | RST | Reset -- abort connection |

### 3.5 Checksum Calculation

1. Set the checksum field to zero
2. Compute CRC32 (IEEE) over the full header bytes + payload bytes
3. Write the resulting 32-bit value into the checksum field

---

## 4. Tunnel Encapsulation

### 4.1 Plaintext Frame

Pilot Protocol packets are encapsulated in real UDP datagrams:

```
[4-byte magic: 0x50494C54 ("PILT")]
[34-byte Pilot Protocol header]
[Payload bytes]
```

### 4.2 Encrypted Frame

When tunnel encryption is active (default):

```
[4-byte magic: 0x50494C53 ("PILS")]
[4-byte sender Node ID]
[12-byte nonce]
[ciphertext + 16-byte GCM tag]
```

Encryption: AES-256-GCM. Key derived from X25519 ECDH exchange.

### 4.3 Key Exchange Frame

Anonymous key exchange (no identity):

```
[4-byte magic: 0x50494C4B ("PILK")]
[4-byte sender Node ID]
[32-byte X25519 public key]
```

### 4.4 Authenticated Key Exchange Frame

Authenticated key exchange (with Ed25519 identity):

```
[4-byte magic: 0x50494C41 ("PILA")]
[4-byte sender Node ID]
[32-byte X25519 public key]
[32-byte Ed25519 public key]
[64-byte Ed25519 signature]
```

The signature covers: `"auth"` + Node ID (4 bytes) + X25519 public key (32 bytes).

---

## 5. Session State Machine

### 5.1 Connection States

`CLOSED` -> `SYN_SENT` / `LISTEN` -> `ESTABLISHED` -> `FIN_WAIT` / `CLOSE_WAIT` -> `TIME_WAIT` -> `CLOSED`

### 5.2 Three-Way Handshake

```
Initiator                    Responder
    |                            |
    |------- SYN seq=X -------->|
    |                            |
    |<--- SYN+ACK seq=Y ack=X+1-|
    |                            |
    |------ ACK ack=Y+1 ------->|
    |                            |
    |      ESTABLISHED           |      ESTABLISHED
```

### 5.3 Connection Teardown

```
Closer                       Remote
    |                            |
    |------- FIN seq=N -------->|
    |                            |
    |<------ ACK ack=N+1 -------|
    |                            |
    |      TIME_WAIT (10s)       |      CLOSED
    |                            |
    |      CLOSED                |
```

### 5.4 Sequence Number Arithmetic

Sequence numbers are 32-bit unsigned integers with wrapping comparison:

```
seqAfter(a, b) = int32(a - b) > 0
```

This follows RFC 1982 serial number arithmetic, correctly handling wraparound at 2^32.

---

## 6. IPC Protocol (Daemon <-> Driver)

Communication over Unix domain socket. Messages framed as:

```
[4-byte big-endian length][message bytes]
```

Maximum message size: 1 MB (1,048,576 bytes).

### 6.1 Commands

| Cmd | Name | Direction | Payload |
|-----|------|-----------|---------|
| 0x01 | Bind | Driver -> Daemon | `[2B port]` |
| 0x02 | BindOK | Daemon -> Driver | `[2B port]` |
| 0x03 | Dial | Driver -> Daemon | `[6B dest addr][2B port]` |
| 0x04 | DialOK | Daemon -> Driver | `[4B conn_id]` |
| 0x05 | Accept | Daemon -> Driver | `[4B conn_id][6B remote addr][2B port]` |
| 0x06 | Send | Driver -> Daemon | `[4B conn_id][NB data]` |
| 0x07 | Recv | Daemon -> Driver | `[4B conn_id][NB data]` |
| 0x08 | Close | Driver -> Daemon | `[4B conn_id]` |
| 0x09 | CloseOK | Daemon -> Driver | `[4B conn_id]` |
| 0x0A | Error | Daemon -> Driver | `[2B error code][NB message]` |
| 0x0B | SendTo | Driver -> Daemon | `[6B dest addr][2B port][NB data]` |
| 0x0C | RecvFrom | Daemon -> Driver | `[6B src addr][2B port][NB data]` |
| 0x0D | Info | Driver -> Daemon | (empty) |
| 0x0E | InfoOK | Daemon -> Driver | `[NB JSON]` |
| 0x0F | Handshake | Driver -> Daemon | `[1B sub-cmd][NB payload]` |
| 0x10 | HandshakeOK | Daemon -> Driver | `[NB JSON]` |

---

## 7. Wire Examples

### 7.1 SYN Packet (no payload)

From `0:0000.0000.0001` port 49152 to `0:0000.0000.0002` port 1000:

```
Byte  0:    0x11         (version=1, flags=SYN)
Byte  1:    0x01         (protocol=Stream)
Byte  2-3:  0x0000       (payload length=0)
Byte  4-5:  0x0000       (src network=0)
Byte  6-9:  0x00000001   (src node=1)
Byte 10-11: 0x0000       (dst network=0)
Byte 12-15: 0x00000002   (dst node=2)
Byte 16-17: 0xC000       (src port=49152)
Byte 18-19: 0x03E8       (dst port=1000)
Byte 20-23: 0x00000000   (seq=0)
Byte 24-27: 0x00000000   (ack=0)
Byte 28-29: 0x0200       (window=512 segments)
Byte 30-33: [CRC32]
```

Total: 34 bytes header + 0 payload.

### 7.2 Data Packet

ACK data packet with 5-byte payload `"hello"`:

```
Byte  0:    0x12         (version=1, flags=ACK)
Byte  1:    0x01         (protocol=Stream)
Byte  2-3:  0x0005       (payload length=5)
Byte  4-5:  0x0000       (src network=0)
Byte  6-9:  0x00000001   (src node=1)
Byte 10-11: 0x0000       (dst network=0)
Byte 12-15: 0x00000002   (dst node=2)
Byte 16-17: 0xC000       (src port=49152)
Byte 18-19: 0x03E8       (dst port=1000)
Byte 20-23: 0x00000001   (seq=1)
Byte 24-27: 0x00000001   (ack=1)
Byte 28-29: 0x01F6       (window=502 segments)
Byte 30-33: [CRC32]
Byte 34-38: 0x68656C6C6F (payload="hello")
```

Total: 34 bytes header + 5 bytes payload = 39 bytes.

### 7.3 Tunnel-Encapsulated Plaintext

```
Byte  0-3:  0x50494C54   (magic="PILT")
Byte  4+:   [34-byte header][payload]
```

### 7.4 Tunnel-Encapsulated Encrypted

```
Byte  0-3:  0x50494C53   (magic="PILS")
Byte  4-7:  0x00000001   (sender node ID=1)
Byte  8-19: [12-byte nonce]
Byte 20+:   [ciphertext + 16-byte GCM tag]
```

---

## 8. Version Negotiation

### 8.1 Version Field

The 4-bit Version field in the packet header identifies the protocol version. The current version is `1`.

### 8.2 SYN Version Handshake

The initiator includes its protocol version in the SYN packet's Version field. The responder checks the version and:

- If the version is supported, echoes the same version in the SYN-ACK.
- If the version is unsupported, sends RST with no payload.

Both sides MUST use the same version for the duration of a connection. There is no version downgrade negotiation — if the versions do not match, the connection is refused.

### 8.3 Non-SYN Packets

For non-SYN packets (data, ACK, FIN), the receiver checks the Version field. If the version does not match the connection's established version, the packet is silently discarded. Implementations SHOULD log discarded packets at debug level.

### 8.4 Future Versions

Future protocol versions MAY extend the header format. Implementations MUST NOT assume a fixed header size based on the version field — they should use the version to determine the header layout. Version `0` is reserved and MUST NOT be used.

---

## 9. Path MTU Considerations

### 9.1 Maximum Segment Size

The default MSS is 4,096 bytes. This is the maximum payload per Pilot Protocol packet before automatic segmentation splits a write into multiple segments.

### 9.2 Encapsulation Overhead

The total overhead per encrypted tunnel packet is:

| Component | Size |
|-----------|------|
| PILS magic | 4 bytes |
| Sender Node ID | 4 bytes |
| GCM nonce | 12 bytes |
| Pilot header | 34 bytes |
| GCM auth tag | 16 bytes |
| **Total overhead** | **70 bytes** |

For plaintext tunnel packets (PILT), the overhead is 4 bytes (magic) + 34 bytes (header) = 38 bytes.

### 9.3 Effective Payload

Given a typical Internet path MTU of 1,500 bytes (Ethernet) and 8 bytes UDP header + 20 bytes IP header:

- Available for Pilot: 1,500 - 28 = 1,472 bytes
- Encrypted payload capacity: 1,472 - 70 = 1,402 bytes
- Plaintext payload capacity: 1,472 - 38 = 1,434 bytes

The default MSS of 4,096 bytes exceeds the typical single-packet capacity. This means most full-MSS segments will be fragmented at the IP layer into 3 IP fragments. This is acceptable on most modern networks but may cause issues on paths with PMTU < 1,500 bytes or where IP fragmentation is blocked.

### 9.4 Recommendations

- For Internet-facing deployments, an MSS of 1,400 bytes avoids IP fragmentation on virtually all paths.
- For local or datacenter deployments, the default 4,096 MSS is safe (typical jumbo frame MTU is 9,000 bytes).
- Implementations SHOULD provide a configurable MSS option.
- Implementations SHOULD NOT set the DF (Don't Fragment) bit on UDP datagrams, allowing IP-layer fragmentation as a fallback.

---

## 10. Nonce Management

### 10.1 Tunnel Encryption Nonces

AES-256-GCM requires a unique 96-bit (12-byte) nonce for every encryption operation under the same key. Nonce reuse under the same key is catastrophic — it allows plaintext recovery and forgery.

### 10.2 Nonce Construction

Each tunnel session generates a nonce as follows:

```
[4-byte random prefix][8-byte monotonic counter]
```

- **Random prefix**: 4 bytes generated from a cryptographically secure random source (`crypto/rand`) when the tunnel session is established. This prefix is unique per session with overwhelming probability.
- **Monotonic counter**: 8-byte unsigned integer, starting at 0, incremented by 1 for each packet encrypted. The counter MUST NOT be reset within a session.

### 10.3 Session Lifecycle

A new tunnel session is established when:

1. Two daemons perform an X25519 key exchange (PILK or PILA frame).
2. Both sides derive a fresh AES-256-GCM key from the ECDH shared secret.
3. Both sides generate a new random nonce prefix.

A new key exchange produces a new key and new nonce prefix. Old nonces cannot collide with new nonces because the key is different.

### 10.4 Counter Exhaustion

The 8-byte counter supports 2^64 packets per session. At 1 million packets per second, a single session would last over 584,000 years before counter exhaustion. Implementations MUST close the tunnel and re-key if the counter reaches 2^64 - 1. In practice, this condition is unreachable.

### 10.5 Application-Layer Nonces (Port 443)

The secure channel on port 443 uses a separate nonce scheme: a monotonically increasing 8-byte counter zero-padded to 12 bytes. Each secure connection has an independent counter starting at 0. Since each connection performs its own X25519 key exchange, nonce uniqueness is guaranteed per-key.
