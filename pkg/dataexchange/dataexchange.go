package dataexchange

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame types for data exchange on port 1001.
const (
	TypeText   uint32 = 1
	TypeBinary uint32 = 2
	TypeJSON   uint32 = 3
	TypeFile   uint32 = 4
)

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
	if length > 1<<24 { // 16MB max
		return nil, fmt.Errorf("frame too large: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	f := &Frame{Type: ftype, Payload: payload}

	if ftype == TypeFile && len(payload) >= 2 {
		nameLen := binary.BigEndian.Uint16(payload[0:2])
		if int(nameLen)+2 <= len(payload) {
			f.Filename = string(payload[2 : 2+nameLen])
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
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
