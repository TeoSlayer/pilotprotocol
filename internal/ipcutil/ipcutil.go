package ipcutil

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxMessageSize is the maximum IPC message size (1MB).
const MaxMessageSize = 1 << 20

// Read reads a length-prefixed IPC message from r.
func Read(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > MaxMessageSize {
		return nil, fmt.Errorf("ipc message too large: %d bytes (max %d)", length, MaxMessageSize)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Write writes a length-prefixed IPC message to w.
func Write(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}
