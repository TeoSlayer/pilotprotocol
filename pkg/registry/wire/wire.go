// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wire defines the binary wire format shared between the registry
// client and server. It contains protocol constants, framing, and the
// encode/decode helpers that both sides use to talk over the same TCP
// connection. Pure types and functions — no networking, no logging, no I/O
// beyond the io.Reader/io.Writer abstractions used by the framing layer.
package wire

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"time"
)

// maxCount caps wire-controlled list lengths to prevent a malicious
// peer from triggering large allocations (e.g. netCount=65535 →
// 130 KB make()). All frames are bounded by MaxMessageSize (64 MiB)
// but per-field allocations without caps can cause memory pressure
// before the overall frame limit is reached.
const maxCount = 1024

// WriteMessageDeadline bounds how long a single JSON response write can
// take. If a client is slow to drain (overloaded host, kernel buffer
// pressure) we'd otherwise hold the request goroutine + response payload
// in memory indefinitely. After this deadline expires, w.Write returns
// an error and the caller can drop the connection cleanly.
const WriteMessageDeadline = 5 * time.Second

// MaxMessageSize is the maximum allowed wire message size (64 MiB).
// Messages exceeding this limit cause the connection to be closed.
// Note: must stay well below the binary wire magic (0x50494C54 ≈ 1.3B)
// for protocol auto-detection to work. Sized for full registry snapshot
// in subscribe_replication: ~26 MiB at 100k+ nodes, with headroom.
const MaxMessageSize = 64 * 1024 * 1024

// Binary wire format for high-throughput operations.
//
// Protocol negotiation: binary clients send magic 0x50494C54 ("PILT") + 1 byte
// version as the first 5 bytes of the connection. The server detects this vs a
// JSON length prefix (which is always < 64KB) and switches mode per-connection.
//
// Binary frame: [4B total_length][1B msg_type][payload]
//
// Message types:
//   0x00 = JSON passthrough (payload is JSON bytes)
//   0x01 = heartbeat request
//   0x81 = heartbeat response
//   0x02 = lookup request
//   0x82 = lookup response
//   0x03 = resolve request
//   0x83 = resolve response
//   0xFF = error response

// Magic is the 4-byte magic sent by binary clients at connection start.
var Magic = [4]byte{0x50, 0x49, 0x4C, 0x54} // "PILT"

// Version is the current binary protocol version.
const Version byte = 1

// Binary message type constants.
const (
	MsgJSON        byte = 0x00
	MsgHeartbeat   byte = 0x01
	MsgHeartbeatOK byte = 0x81
	MsgLookup      byte = 0x02
	MsgLookupOK    byte = 0x82
	MsgResolve     byte = 0x03
	MsgResolveOK   byte = 0x83
	MsgError       byte = 0xFF
)

// ReadFrame reads a single binary frame: [4B length][1B type][payload].
func ReadFrame(r io.Reader) (msgType byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	if length < 1 {
		return 0, nil, fmt.Errorf("binary frame too short")
	}
	if length > MaxMessageSize {
		return 0, nil, fmt.Errorf("binary frame too large: %d bytes (max %d)", length, MaxMessageSize)
	}
	msgType = hdr[4]
	payloadLen := length - 1 // length includes the type byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

// WriteFrame writes a single binary frame.
func WriteFrame(w io.Writer, msgType byte, payload []byte) error {
	length := uint32(1 + len(payload)) // type byte + payload
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], length)
	hdr[4] = msgType
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// --- Heartbeat ---

// HeartbeatReq holds a decoded binary heartbeat request: [4B node_id][64B signature].
type HeartbeatReq struct {
	NodeID    uint32
	Signature [64]byte
}

// EncodeHeartbeatReq encodes a heartbeat request payload.
func EncodeHeartbeatReq(nodeID uint32, sig []byte) []byte {
	buf := make([]byte, 4+64)
	binary.BigEndian.PutUint32(buf[:4], nodeID)
	copy(buf[4:], sig)
	return buf
}

// DecodeHeartbeatReq decodes a heartbeat request payload.
func DecodeHeartbeatReq(payload []byte) (HeartbeatReq, error) {
	if len(payload) < 68 {
		return HeartbeatReq{}, fmt.Errorf("heartbeat request too short: %d bytes", len(payload))
	}
	var req HeartbeatReq
	req.NodeID = binary.BigEndian.Uint32(payload[:4])
	copy(req.Signature[:], payload[4:68])
	return req, nil
}

// EncodeHeartbeatResp encodes the heartbeat response: [8B unix_time][1B flags].
// flags bit0 = key_expiry_warning.
func EncodeHeartbeatResp(unixTime int64, keyExpiryWarning bool) []byte {
	buf := make([]byte, 9)
	binary.BigEndian.PutUint64(buf[:8], uint64(unixTime))
	if keyExpiryWarning {
		buf[8] = 1
	}
	return buf
}

// DecodeHeartbeatResp decodes a heartbeat response.
func DecodeHeartbeatResp(payload []byte) (unixTime int64, keyExpiryWarning bool, err error) {
	if len(payload) < 9 {
		return 0, false, fmt.Errorf("heartbeat response too short: %d bytes", len(payload))
	}
	unixTime = int64(binary.BigEndian.Uint64(payload[:8]))
	keyExpiryWarning = payload[8]&1 != 0
	return unixTime, keyExpiryWarning, nil
}

// --- Lookup ---

// EncodeLookupReq encodes a lookup request: [4B node_id].
func EncodeLookupReq(nodeID uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, nodeID)
	return buf
}

// DecodeLookupReq decodes a lookup request.
func DecodeLookupReq(payload []byte) (uint32, error) {
	if len(payload) < 4 {
		return 0, fmt.Errorf("lookup request too short: %d bytes", len(payload))
	}
	return binary.BigEndian.Uint32(payload[:4]), nil
}

// EncodeLookupResp encodes a lookup response.
// Format: [4B node_id][1B flags][4B reserved][2B net_count][net_ids...]
//
//	[1B pubkey_len][pubkey...][1B hostname_len][hostname...]
//	[1B tags_count][for each: 1B len, bytes...][2B addr_len][addr...]
//	[1B extid_len][extid...]
//
// The 4-byte reserved field was formerly polo_score; it is written as zero
// and ignored on decode to preserve wire-format compatibility.
func EncodeLookupResp(nodeID uint32, public, taskExec bool,
	networks []uint16, pubKey []byte, hostname string, tags []string,
	realAddr string, externalID string) []byte {

	// Calculate size
	size := 4 + 1 + 4 + 2 + len(networks)*2 // node_id + flags + reserved + nets
	size += 1 + len(pubKey)                 // pubkey
	size += 1 + len(hostname)               // hostname
	size += 1                               // tags count
	for _, t := range tags {
		size += 1 + len(t) // tag len + tag
	}
	size += 2 + len(realAddr)   // real_addr (only if public)
	size += 1 + len(externalID) // external_id

	buf := make([]byte, 0, size)

	// node_id
	buf = binary.BigEndian.AppendUint32(buf, nodeID)

	// flags
	var flags byte
	if public {
		flags |= 0x01
	}
	if taskExec {
		flags |= 0x02
	}
	buf = append(buf, flags)

	// reserved (was polo_score) — always zero
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// networks
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(networks)))
	for _, n := range networks {
		buf = binary.BigEndian.AppendUint16(buf, n)
	}

	// pubkey
	if len(pubKey) > 255 {
		pubKey = pubKey[:255]
	}
	buf = append(buf, byte(len(pubKey)))
	buf = append(buf, pubKey...)

	// hostname
	if len(hostname) > 255 {
		hostname = hostname[:255]
	}
	buf = append(buf, byte(len(hostname)))
	buf = append(buf, []byte(hostname)...)

	// tags
	if len(tags) > 255 {
		tags = tags[:255]
	}
	buf = append(buf, byte(len(tags)))
	for _, t := range tags {
		if len(t) > 255 {
			t = t[:255]
		}
		buf = append(buf, byte(len(t)))
		buf = append(buf, []byte(t)...)
	}

	// real_addr
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(realAddr)))
	buf = append(buf, []byte(realAddr)...)

	// external_id
	if len(externalID) > 255 {
		externalID = externalID[:255]
	}
	buf = append(buf, byte(len(externalID)))
	buf = append(buf, []byte(externalID)...)

	return buf
}

// --- Resolve ---

// EncodeResolveReq encodes a resolve request: [4B node_id][4B requester_id][64B signature].
func EncodeResolveReq(nodeID, requesterID uint32, sig []byte) []byte {
	buf := make([]byte, 4+4+64)
	binary.BigEndian.PutUint32(buf[:4], nodeID)
	binary.BigEndian.PutUint32(buf[4:8], requesterID)
	copy(buf[8:], sig)
	return buf
}

// DecodeResolveReq decodes a resolve request.
func DecodeResolveReq(payload []byte) (nodeID, requesterID uint32, sig []byte, err error) {
	if len(payload) < 72 {
		return 0, 0, nil, fmt.Errorf("resolve request too short: %d bytes", len(payload))
	}
	nodeID = binary.BigEndian.Uint32(payload[:4])
	requesterID = binary.BigEndian.Uint32(payload[4:8])
	sig = payload[8:72]
	return nodeID, requesterID, sig, nil
}

// EncodeResolveResp encodes a resolve response.
// Format: [4B node_id][2B addr_len][addr...][2B lan_count][for each: 2B len, addr...]
//
//	[4B key_age_days]  (math.MaxUint32 if unknown)
func EncodeResolveResp(nodeID uint32, realAddr string, lanAddrs []string, keyAgeDays int) []byte {
	size := 4 + 2 + len(realAddr) + 2 + 4
	for _, la := range lanAddrs {
		size += 2 + len(la)
	}
	buf := make([]byte, 0, size)

	buf = binary.BigEndian.AppendUint32(buf, nodeID)

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(realAddr)))
	buf = append(buf, []byte(realAddr)...)

	buf = binary.BigEndian.AppendUint16(buf, uint16(len(lanAddrs)))
	for _, la := range lanAddrs {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(la)))
		buf = append(buf, []byte(la)...)
	}

	if keyAgeDays < 0 {
		buf = binary.BigEndian.AppendUint32(buf, math.MaxUint32)
	} else {
		buf = binary.BigEndian.AppendUint32(buf, uint32(keyAgeDays))
	}

	return buf
}

// --- Error ---

// EncodeError encodes an error message frame payload.
func EncodeError(msg string) []byte {
	if len(msg) > 65000 {
		msg = msg[:65000]
	}
	buf := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msg)))
	copy(buf[2:], msg)
	return buf
}

// DecodeError decodes an error message frame payload.
func DecodeError(payload []byte) string {
	if len(payload) < 2 {
		return "unknown error"
	}
	length := binary.BigEndian.Uint16(payload[:2])
	if int(length) > len(payload)-2 {
		length = uint16(len(payload) - 2)
	}
	return string(payload[2 : 2+length])
}

// --- Lookup response decoder (client-side) ---

// LookupResult holds the decoded fields from a binary lookup response.
type LookupResult struct {
	NodeID     uint32
	Public     bool
	TaskExec   bool
	Networks   []uint16
	PubKey     []byte
	Hostname   string
	Tags       []string
	RealAddr   string
	ExternalID string
}

// DecodeLookupResp decodes a binary lookup response.
func DecodeLookupResp(payload []byte) (LookupResult, error) {
	var r LookupResult
	if len(payload) < 11 {
		return r, fmt.Errorf("lookup response too short: %d bytes", len(payload))
	}

	off := 0
	r.NodeID = binary.BigEndian.Uint32(payload[off : off+4])
	off += 4
	flags := payload[off]
	off++
	r.Public = flags&0x01 != 0
	r.TaskExec = flags&0x02 != 0
	off += 4 // skip reserved field (was polo_score)

	if off+2 > len(payload) {
		return r, fmt.Errorf("truncated network count")
	}
	netCount := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if netCount > maxCount {
		return r, fmt.Errorf("network count %d exceeds cap %d", netCount, maxCount)
	}
	r.Networks = make([]uint16, netCount)
	for i := 0; i < netCount; i++ {
		if off+2 > len(payload) {
			return r, fmt.Errorf("truncated networks at index %d", i)
		}
		r.Networks[i] = binary.BigEndian.Uint16(payload[off : off+2])
		off += 2
	}

	if off >= len(payload) {
		return r, fmt.Errorf("truncated pubkey length")
	}
	pkLen := int(payload[off])
	off++
	if off+pkLen > len(payload) {
		return r, fmt.Errorf("truncated pubkey data")
	}
	if pkLen > 0 {
		r.PubKey = make([]byte, pkLen)
		copy(r.PubKey, payload[off:off+pkLen])
	}
	off += pkLen

	if off >= len(payload) {
		return r, fmt.Errorf("truncated hostname length")
	}
	hnLen := int(payload[off])
	off++
	if off+hnLen > len(payload) {
		return r, fmt.Errorf("truncated hostname data")
	}
	r.Hostname = string(payload[off : off+hnLen])
	off += hnLen

	if off >= len(payload) {
		return r, fmt.Errorf("truncated tags count")
	}
	tagCount := int(payload[off])
	off++
	if tagCount > maxCount {
		return r, fmt.Errorf("tag count %d exceeds cap %d", tagCount, maxCount)
	}
	r.Tags = make([]string, tagCount)
	for i := 0; i < tagCount; i++ {
		if off >= len(payload) {
			return r, fmt.Errorf("truncated tag length at index %d", i)
		}
		tLen := int(payload[off])
		off++
		if off+tLen > len(payload) {
			return r, fmt.Errorf("truncated tag data at index %d", i)
		}
		r.Tags[i] = string(payload[off : off+tLen])
		off += tLen
	}

	if off+2 > len(payload) {
		return r, fmt.Errorf("truncated real_addr length")
	}
	addrLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if off+addrLen > len(payload) {
		return r, fmt.Errorf("truncated real_addr data")
	}
	r.RealAddr = string(payload[off : off+addrLen])
	off += addrLen

	if off >= len(payload) {
		return r, fmt.Errorf("truncated external_id length")
	}
	eidLen := int(payload[off])
	off++
	if off+eidLen > len(payload) {
		return r, fmt.Errorf("truncated external_id data")
	}
	r.ExternalID = string(payload[off : off+eidLen])

	return r, nil
}

// --- Resolve response decoder (client-side) ---

// ResolveResult holds the decoded fields from a binary resolve response.
type ResolveResult struct {
	NodeID     uint32
	RealAddr   string
	LANAddrs   []string
	KeyAgeDays int // -1 if unknown
}

// DecodeResolveResp decodes a binary resolve response.
func DecodeResolveResp(payload []byte) (ResolveResult, error) {
	var r ResolveResult
	if len(payload) < 12 {
		return r, fmt.Errorf("resolve response too short: %d bytes", len(payload))
	}

	off := 0
	r.NodeID = binary.BigEndian.Uint32(payload[off : off+4])
	off += 4

	if off+2 > len(payload) {
		return r, fmt.Errorf("truncated addr length")
	}
	addrLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if off+addrLen > len(payload) {
		return r, fmt.Errorf("truncated addr data")
	}
	r.RealAddr = string(payload[off : off+addrLen])
	off += addrLen

	if off+2 > len(payload) {
		return r, fmt.Errorf("truncated lan_addrs count")
	}
	lanCount := int(binary.BigEndian.Uint16(payload[off : off+2]))
	off += 2
	if lanCount > maxCount {
		return r, fmt.Errorf("lan_addrs count %d exceeds cap %d", lanCount, maxCount)
	}
	r.LANAddrs = make([]string, lanCount)
	for i := 0; i < lanCount; i++ {
		if off+2 > len(payload) {
			return r, fmt.Errorf("truncated lan addr length at index %d", i)
		}
		laLen := int(binary.BigEndian.Uint16(payload[off : off+2]))
		off += 2
		if off+laLen > len(payload) {
			return r, fmt.Errorf("truncated lan addr data at index %d", i)
		}
		r.LANAddrs[i] = string(payload[off : off+laLen])
		off += laLen
	}

	if off+4 > len(payload) {
		return r, fmt.Errorf("truncated key_age_days")
	}
	raw := binary.BigEndian.Uint32(payload[off : off+4])
	if raw == math.MaxUint32 {
		r.KeyAgeDays = -1
	} else {
		r.KeyAgeDays = int(raw)
	}

	return r, nil
}

// --- JSON message framing ---
//
// The non-binary JSON protocol uses a 4-byte big-endian length prefix
// followed by a JSON body. ReadMessage/WriteMessage are the helpers both
// the client and the server use over the same TCP connection.

// ReadMessage reads a length-prefixed JSON message from r and decodes
// it into a map.
func ReadMessage(r io.Reader) (map[string]interface{}, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, MaxMessageSize)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return msg, nil
}

// WriteMessage writes a length-prefixed JSON-encoded message to w.
// If w is a net.Conn, a write deadline is applied.
func WriteMessage(w io.Writer, msg map[string]interface{}) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("json encode: %w", err)
	}
	return WriteRawMessage(w, body)
}

// WriteRawMessage writes a length-prefixed raw JSON body to w.
// Callers that have already produced the JSON bytes (e.g., a list-nodes
// cache hit) can skip the json.Marshal step.
func WriteRawMessage(w io.Writer, body []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))

	if c, ok := w.(net.Conn); ok {
		_ = c.SetWriteDeadline(time.Now().Add(WriteMessageDeadline))
		defer c.SetWriteDeadline(time.Time{})
	}

	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}
