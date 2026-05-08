// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Frame types for data exchange on port 1001.
const (
	TypeText   uint32 = 1
	TypeBinary uint32 = 2
	TypeJSON   uint32 = 3
	TypeFile   uint32 = 4
	// TypeTrace wraps another frame type with nanosecond-precision timing.
	// Wire layout: [4-byte TypeTrace][4-byte len][4-byte inner_type][8-byte sent_at_ns][inner_payload]
	TypeTrace uint32 = 5
)

// TraceFrame carries timing metadata around an inner message frame.
type TraceFrame struct {
	SentAtNs  int64
	InnerType uint32
	Payload   []byte
}

// WriteTraceFrame serialises a TraceFrame as a TypeTrace outer frame.
func WriteTraceFrame(w io.Writer, tf *TraceFrame) error {
	buf := make([]byte, 12+len(tf.Payload))
	binary.BigEndian.PutUint32(buf[0:4], tf.InnerType)
	binary.BigEndian.PutUint64(buf[4:12], uint64(tf.SentAtNs))
	copy(buf[12:], tf.Payload)
	return WriteFrame(w, &Frame{Type: TypeTrace, Payload: buf})
}

// ReadTracePayload decodes a TraceFrame from a raw TypeTrace Frame.
func ReadTracePayload(f *Frame) (*TraceFrame, error) {
	if f.Type != TypeTrace {
		return nil, fmt.Errorf("expected TypeTrace, got %d", f.Type)
	}
	if len(f.Payload) < 12 {
		return nil, fmt.Errorf("trace payload too short: %d bytes", len(f.Payload))
	}
	return &TraceFrame{
		InnerType: binary.BigEndian.Uint32(f.Payload[0:4]),
		SentAtNs:  int64(binary.BigEndian.Uint64(f.Payload[4:12])),
		Payload:   f.Payload[12:],
	}, nil
}

// maxFilenameLen limits filename length to prevent abuse.
const maxFilenameLen = 255

// MaxFrameSize caps a single data-exchange frame at 256 MiB. Sized to fit
// the test fleet's 100 MiB file payloads with margin while still rejecting
// pathological 500 MiB+ frames that would dominate memory.
const MaxFrameSize = 1 << 28

// Frame is a typed data unit exchanged between agents.
// Wire format: [4-byte type][4-byte length][payload]
// For TypeFile, payload is: [2-byte name length][name bytes][file data]
type Frame struct {
	Type     uint32
	Payload  []byte
	Filename string // only for TypeFile
}

// WriteFrame writes a frame to a writer.
func WriteFrame(w io.Writer, f *Frame) error {
	payload := f.Payload
	if f.Type == TypeFile {
		// Prepend filename
		name := []byte(f.Filename)
		payload = make([]byte, 2+len(name)+len(f.Payload))
		binary.BigEndian.PutUint16(payload[0:2], uint16(len(name)))
		copy(payload[2:], name)
		copy(payload[2+len(name):], f.Payload)
	}

	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], f.Type)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads a frame from a reader.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	ftype := binary.BigEndian.Uint32(hdr[0:4])
	length := binary.BigEndian.Uint32(hdr[4:8])
	if length > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d (max %d)", length, MaxFrameSize)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	f := &Frame{Type: ftype, Payload: payload}

	if ftype == TypeFile && len(payload) >= 2 {
		nameLen := binary.BigEndian.Uint16(payload[0:2])
		if int(nameLen)+2 <= len(payload) {
			if nameLen > maxFilenameLen {
				return nil, fmt.Errorf("filename too long: %d bytes (max %d)", nameLen, maxFilenameLen)
			}
			name := string(payload[2 : 2+nameLen])
			if strings.ContainsAny(name, "/\\") {
				return nil, fmt.Errorf("invalid filename: path traversal characters not allowed")
			}
			if name != "" {
				f.Filename = filepath.Base(name)
				if f.Filename == "." || f.Filename == ".." {
					return nil, fmt.Errorf("invalid filename: path traversal name %q not allowed", f.Filename)
				}
			}
			f.Payload = payload[2+nameLen:]
		}
	}

	return f, nil
}

// TypeName returns a human-readable name for a frame type.
func TypeName(t uint32) string {
	switch t {
	case TypeText:
		return "TEXT"
	case TypeBinary:
		return "BINARY"
	case TypeJSON:
		return "JSON"
	case TypeFile:
		return "FILE"
	case TypeTrace:
		return "TRACE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
