package tests

import (
	"bytes"
	"testing"

	"web4/pkg/dataexchange"
)

func TestFrameTextRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &dataexchange.Frame{
		Type:    dataexchange.TypeText,
		Payload: []byte("hello world"),
	}

	if err := dataexchange.WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Type != original.Type {
		t.Fatalf("type: expected %d, got %d", original.Type, got.Type)
	}
	if !bytes.Equal(got.Payload, original.Payload) {
		t.Fatalf("payload: expected %q, got %q", original.Payload, got.Payload)
	}
}

func TestFrameBinaryRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	original := &dataexchange.Frame{
		Type:    dataexchange.TypeBinary,
		Payload: data,
	}

	if err := dataexchange.WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Type != dataexchange.TypeBinary {
		t.Fatalf("type: expected BINARY, got %d", got.Type)
	}
	if !bytes.Equal(got.Payload, data) {
		t.Fatalf("payload mismatch: len expected %d, got %d", len(data), len(got.Payload))
	}
}

func TestFrameJSONRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	json := []byte(`{"key":"value","num":42}`)
	original := &dataexchange.Frame{
		Type:    dataexchange.TypeJSON,
		Payload: json,
	}

	if err := dataexchange.WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Type != dataexchange.TypeJSON {
		t.Fatalf("type: expected JSON, got %d", got.Type)
	}
	if string(got.Payload) != string(json) {
		t.Fatalf("payload: expected %s, got %s", json, got.Payload)
	}
}

func TestFrameFileRoundTrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &dataexchange.Frame{
		Type:     dataexchange.TypeFile,
		Filename: "test.txt",
		Payload:  []byte("file contents here"),
	}

	if err := dataexchange.WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Type != dataexchange.TypeFile {
		t.Fatalf("type: expected FILE, got %d", got.Type)
	}
	if got.Filename != "test.txt" {
		t.Fatalf("filename: expected %q, got %q", "test.txt", got.Filename)
	}
	if string(got.Payload) != "file contents here" {
		t.Fatalf("payload: expected %q, got %q", "file contents here", string(got.Payload))
	}
}

func TestFrameEmptyPayload(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &dataexchange.Frame{
		Type:    dataexchange.TypeText,
		Payload: []byte{},
	}

	if err := dataexchange.WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if len(got.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got.Payload))
	}
}

func TestFrameTooLarge(t *testing.T) {
	t.Parallel()
	// Craft a header with length > 16MB
	var buf bytes.Buffer
	hdr := make([]byte, 8)
	hdr[0] = 0
	hdr[1] = 0
	hdr[2] = 0
	hdr[3] = 1 // type = text
	hdr[4] = 0x02
	hdr[5] = 0x00
	hdr[6] = 0x00
	hdr[7] = 0x00 // length = 33554432 (32MB)
	buf.Write(hdr)

	_, err := dataexchange.ReadFrame(&buf)
	if err == nil {
		t.Fatal("expected error for oversized frame, got nil")
	}
}

func TestFrameMultipleSequential(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	frames := []*dataexchange.Frame{
		{Type: dataexchange.TypeText, Payload: []byte("first")},
		{Type: dataexchange.TypeJSON, Payload: []byte(`{"n":2}`)},
		{Type: dataexchange.TypeBinary, Payload: []byte{0xFF, 0x00, 0xAA}},
	}

	for _, f := range frames {
		if err := dataexchange.WriteFrame(&buf, f); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	for i, expected := range frames {
		got, err := dataexchange.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if got.Type != expected.Type {
			t.Fatalf("frame %d: expected type %d, got %d", i, expected.Type, got.Type)
		}
		if !bytes.Equal(got.Payload, expected.Payload) {
			t.Fatalf("frame %d: payload mismatch", i)
		}
	}
}

func TestFrameTypeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ftype uint32
		name  string
	}{
		{dataexchange.TypeText, "TEXT"},
		{dataexchange.TypeBinary, "BINARY"},
		{dataexchange.TypeJSON, "JSON"},
		{dataexchange.TypeFile, "FILE"},
		{99, "UNKNOWN(99)"},
	}

	for _, tc := range tests {
		got := dataexchange.TypeName(tc.ftype)
		if got != tc.name {
			t.Errorf("TypeName(%d): expected %q, got %q", tc.ftype, tc.name, got)
		}
	}
}

func TestFrameFileEmptyName(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer

	original := &dataexchange.Frame{
		Type:     dataexchange.TypeFile,
		Filename: "",
		Payload:  []byte("data"),
	}

	if err := dataexchange.WriteFrame(&buf, original); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got.Type != dataexchange.TypeFile {
		t.Fatalf("type: expected FILE, got %d", got.Type)
	}
	if got.Filename != "" {
		t.Fatalf("filename: expected empty, got %q", got.Filename)
	}
	if string(got.Payload) != "data" {
		t.Fatalf("payload: expected %q, got %q", "data", string(got.Payload))
	}
}
