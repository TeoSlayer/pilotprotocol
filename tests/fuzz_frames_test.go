package tests

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/eventstream"
)

// ---------------------------------------------------------------------------
// Data Exchange fuzz targets
// ---------------------------------------------------------------------------

func FuzzDataExchangeReadFrame(f *testing.F) {
	// Valid text frame
	var buf bytes.Buffer
	dataexchange.WriteFrame(&buf, &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("hi")})
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, 8)) // header only, length 0
	f.Add(bytes.Repeat([]byte{0xFF}, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		// Must not panic
		_, _ = dataexchange.ReadFrame(r)
	})
}

func FuzzDataExchangeRoundTrip(f *testing.F) {
	f.Add(uint32(1), []byte("hello"))
	f.Add(uint32(2), []byte{0x00, 0xFF})
	f.Add(uint32(3), []byte(`{"key":"value"}`))
	f.Add(uint32(99), []byte{})

	f.Fuzz(func(t *testing.T, ftype uint32, payload []byte) {
		if len(payload) > 1<<20 { // keep manageable
			payload = payload[:1<<20]
		}

		frame := &dataexchange.Frame{Type: ftype, Payload: payload}
		var buf bytes.Buffer
		if err := dataexchange.WriteFrame(&buf, frame); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}

		got, err := dataexchange.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}

		if got.Type != ftype {
			t.Errorf("type: %d != %d", got.Type, ftype)
		}
		// For non-file types, payload should match directly
		if ftype != dataexchange.TypeFile {
			if !bytes.Equal(got.Payload, payload) {
				t.Error("payload mismatch")
			}
		}
	})
}

func FuzzDataExchangeFileFrame(f *testing.F) {
	// Build a valid file frame
	var buf bytes.Buffer
	dataexchange.WriteFrame(&buf, &dataexchange.Frame{
		Type: dataexchange.TypeFile, Payload: []byte("file-data"), Filename: "test.txt",
	})
	f.Add(buf.Bytes())

	// Adversarial: nameLen > payload
	var bad bytes.Buffer
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], dataexchange.TypeFile)
	binary.BigEndian.PutUint32(hdr[4:8], 4) // 4 bytes payload
	bad.Write(hdr[:])
	var nl [2]byte
	binary.BigEndian.PutUint16(nl[:], 1000) // nameLen = 1000, but only 2 bytes follow
	bad.Write(nl[:])
	bad.Write([]byte{0xAA, 0xBB})
	f.Add(bad.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = dataexchange.ReadFrame(r)
	})
}

// ---------------------------------------------------------------------------
// Event Stream fuzz targets
// ---------------------------------------------------------------------------

func FuzzEventStreamReadEvent(f *testing.F) {
	var buf bytes.Buffer
	eventstream.WriteEvent(&buf, &eventstream.Event{Topic: "test", Payload: []byte("data")})
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 50))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = eventstream.ReadEvent(r)
	})
}

func FuzzEventStreamRoundTrip(f *testing.F) {
	f.Add("test-topic", []byte("payload"))
	f.Add("", []byte{})
	f.Add(strings.Repeat("x", 1024), []byte{0xFF})

	f.Fuzz(func(t *testing.T, topic string, payload []byte) {
		if len(topic) > 1024 || len(payload) > 1<<20 {
			return // skip oversized inputs — they'd be rejected
		}

		evt := &eventstream.Event{Topic: topic, Payload: payload}
		var buf bytes.Buffer
		if err := eventstream.WriteEvent(&buf, evt); err != nil {
			t.Fatalf("WriteEvent: %v", err)
		}

		got, err := eventstream.ReadEvent(&buf)
		if err != nil {
			t.Fatalf("ReadEvent: %v", err)
		}

		if got.Topic != topic {
			t.Errorf("topic: %q != %q", got.Topic, topic)
		}
		if !bytes.Equal(got.Payload, payload) {
			t.Error("payload mismatch")
		}
	})
}

// ---------------------------------------------------------------------------
// Data Exchange edge case unit tests
// ---------------------------------------------------------------------------

func TestDataExchangeFrameLengthZero(t *testing.T) {
	var buf bytes.Buffer
	f := &dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte{}}
	if err := dataexchange.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(got.Payload))
	}
}

func TestDataExchangeFrameExactBoundary(t *testing.T) {
	// length = 1<<24 exactly — should be rejected
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], dataexchange.TypeText)
	binary.BigEndian.PutUint32(hdr[4:8], 1<<24)
	r := bytes.NewReader(hdr[:])
	_, err := dataexchange.ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for frame length = 1<<24")
	}
}

func TestDataExchangeFrameJustUnderBoundary(t *testing.T) {
	// length = 1<<24 - 1 — just under limit (valid length, but truncated read)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], dataexchange.TypeText)
	binary.BigEndian.PutUint32(hdr[4:8], (1<<24)-1)
	r := bytes.NewReader(hdr[:])
	_, err := dataexchange.ReadFrame(r)
	// Should fail due to truncated payload read, not the length check
	if err == nil {
		t.Fatal("expected error for truncated read")
	}
}

func TestDataExchangeFrameUnknownType(t *testing.T) {
	for _, ftype := range []uint32{0, 5, 0xFFFFFFFF} {
		var buf bytes.Buffer
		f := &dataexchange.Frame{Type: ftype, Payload: []byte("x")}
		if err := dataexchange.WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame type %d: %v", ftype, err)
		}
		got, err := dataexchange.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame type %d: %v", ftype, err)
		}
		if got.Type != ftype {
			t.Errorf("type: %d != %d", got.Type, ftype)
		}
	}
}

func TestDataExchangeFileFrameNameLenOverflow(t *testing.T) {
	// File frame where nameLen > actual payload
	var buf bytes.Buffer
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], dataexchange.TypeFile)
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[0:2], 5000) // nameLen = 5000 but only 2 bytes follow
	payload = append(payload[:2], 0xAA, 0xBB)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	// nameLen > payload, so filename should NOT be extracted
	if got.Filename != "" {
		t.Fatalf("expected empty filename for overflow nameLen, got %q", got.Filename)
	}
}

func TestDataExchangeFileFrameNameLenZero(t *testing.T) {
	var buf bytes.Buffer
	f := &dataexchange.Frame{Type: dataexchange.TypeFile, Filename: "", Payload: []byte("data")}
	if err := dataexchange.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Filename != "" {
		t.Fatalf("expected empty filename, got %q", got.Filename)
	}
}

func TestDataExchangeFileFramePayloadTooShort(t *testing.T) {
	// File frame with payload < 2 bytes
	var buf bytes.Buffer
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], dataexchange.TypeFile)
	binary.BigEndian.PutUint32(hdr[4:8], 1) // 1 byte payload
	buf.Write(hdr[:])
	buf.WriteByte(0x42)

	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	// Payload is too short for filename extraction
	if got.Filename != "" {
		t.Fatal("expected empty filename for 1-byte payload")
	}
}

func TestDataExchangeSequentialFrames(t *testing.T) {
	var buf bytes.Buffer
	frames := []*dataexchange.Frame{
		{Type: dataexchange.TypeText, Payload: []byte("one")},
		{Type: dataexchange.TypeBinary, Payload: []byte{0xDE, 0xAD}},
		{Type: dataexchange.TypeJSON, Payload: []byte(`{"k":"v"}`)},
	}
	for _, f := range frames {
		if err := dataexchange.WriteFrame(&buf, f); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for i, want := range frames {
		got, err := dataexchange.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if got.Type != want.Type || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("frame[%d] mismatch", i)
		}
	}
	// Should be EOF
	_, err := dataexchange.ReadFrame(&buf)
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestDataExchangeTypeName(t *testing.T) {
	cases := map[uint32]string{
		dataexchange.TypeText:   "TEXT",
		dataexchange.TypeBinary: "BINARY",
		dataexchange.TypeJSON:   "JSON",
		dataexchange.TypeFile:   "FILE",
		99:                      "UNKNOWN(99)",
	}
	for k, v := range cases {
		if dataexchange.TypeName(k) != v {
			t.Errorf("TypeName(%d) = %q, want %q", k, dataexchange.TypeName(k), v)
		}
	}
}

// ---------------------------------------------------------------------------
// Event Stream edge case unit tests
// ---------------------------------------------------------------------------

func TestEventTopicLengthZero(t *testing.T) {
	var buf bytes.Buffer
	evt := &eventstream.Event{Topic: "", Payload: []byte("data")}
	if err := eventstream.WriteEvent(&buf, evt); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	got, err := eventstream.ReadEvent(&buf)
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if got.Topic != "" {
		t.Fatalf("expected empty topic, got %q", got.Topic)
	}
}

func TestEventTopicLength1024(t *testing.T) {
	topic := strings.Repeat("x", 1024)
	var buf bytes.Buffer
	evt := &eventstream.Event{Topic: topic, Payload: []byte("ok")}
	if err := eventstream.WriteEvent(&buf, evt); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	got, err := eventstream.ReadEvent(&buf)
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if got.Topic != topic {
		t.Fatal("topic mismatch at boundary 1024")
	}
}

func TestEventTopicLength1025(t *testing.T) {
	topic := strings.Repeat("x", 1025)
	var buf bytes.Buffer
	// Write manually: topic len (2 bytes) + topic + payload len (4 bytes)
	binary.Write(&buf, binary.BigEndian, uint16(1025))
	buf.WriteString(topic)
	binary.Write(&buf, binary.BigEndian, uint32(0))

	_, err := eventstream.ReadEvent(&buf)
	if err == nil {
		t.Fatal("expected error for topic length 1025")
	}
}

func TestEventPayloadBoundary(t *testing.T) {
	// Payload length = 1<<24 + 1 — should be rejected
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(4)) // topic len
	buf.WriteString("test")
	binary.Write(&buf, binary.BigEndian, uint32((1<<24)+1)) // too large

	_, err := eventstream.ReadEvent(&buf)
	if err == nil {
		t.Fatal("expected error for payload > 1<<24")
	}
}

func TestEventPayloadExactBoundary(t *testing.T) {
	// Payload length = 1<<24 — exactly at boundary
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint16(4))
	buf.WriteString("test")
	binary.Write(&buf, binary.BigEndian, uint32(1<<24))

	_, err := eventstream.ReadEvent(&buf)
	// Should fail — 1<<24 is > 1<<24 is false; 1<<24 == 1<<24 is not > so it passes the check,
	// but then the read will fail due to truncated data
	// The check is "pl > 1<<24" so exactly 1<<24 is NOT rejected — it's the truncated read that fails
	if err == nil {
		t.Fatal("expected error for truncated read")
	}
}

func TestEventNullBytesInTopic(t *testing.T) {
	topic := "test\x00null"
	var buf bytes.Buffer
	evt := &eventstream.Event{Topic: topic, Payload: []byte("ok")}
	if err := eventstream.WriteEvent(&buf, evt); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	got, err := eventstream.ReadEvent(&buf)
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if got.Topic != topic {
		t.Fatalf("topic with null bytes: %q != %q", got.Topic, topic)
	}
}

func TestEventSequentialEvents(t *testing.T) {
	var buf bytes.Buffer
	events := []*eventstream.Event{
		{Topic: "a", Payload: []byte("1")},
		{Topic: "b", Payload: []byte("2")},
		{Topic: "c", Payload: []byte("3")},
	}
	for _, e := range events {
		if err := eventstream.WriteEvent(&buf, e); err != nil {
			t.Fatalf("WriteEvent: %v", err)
		}
	}
	for i, want := range events {
		got, err := eventstream.ReadEvent(&buf)
		if err != nil {
			t.Fatalf("ReadEvent[%d]: %v", i, err)
		}
		if got.Topic != want.Topic || !bytes.Equal(got.Payload, want.Payload) {
			t.Fatalf("event[%d] mismatch", i)
		}
	}
}

func TestDataExchangeFileRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	f := &dataexchange.Frame{
		Type:     dataexchange.TypeFile,
		Filename: "report.csv",
		Payload:  []byte("col1,col2\nval1,val2"),
	}
	if err := dataexchange.WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := dataexchange.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Type != dataexchange.TypeFile {
		t.Fatalf("type: %d != %d", got.Type, dataexchange.TypeFile)
	}
	if got.Filename != "report.csv" {
		t.Fatalf("filename: %q", got.Filename)
	}
	if !bytes.Equal(got.Payload, []byte("col1,col2\nval1,val2")) {
		t.Fatalf("payload: %q", got.Payload)
	}
}

func TestDataExchangeFrameLargeBoundary(t *testing.T) {
	// length > 1<<24 should be rejected
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], 1)
	binary.BigEndian.PutUint32(hdr[4:8], (1<<24)+1)
	r := bytes.NewReader(hdr[:])
	_, err := dataexchange.ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for frame too large")
	}
}
