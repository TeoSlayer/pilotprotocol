package tests

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/ipcutil"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzIPCRead(f *testing.F) {
	// Valid message
	var buf bytes.Buffer
	ipcutil.Write(&buf, []byte("hello"))
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, 4))                    // length=0
	f.Add(bytes.Repeat([]byte{0xFF}, 8))       // huge length
	f.Add([]byte{0x00, 0x00, 0x00, 0x01})     // length=1, no payload
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 'A'}) // length=1, 1 byte payload

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = ipcutil.Read(r)
	})
}

func FuzzIPCRoundTrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xFF}, 1024))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > ipcutil.MaxMessageSize {
			return
		}
		var buf bytes.Buffer
		if err := ipcutil.Write(&buf, payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got, err := ipcutil.Read(&buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("round-trip mismatch")
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case unit tests
// ---------------------------------------------------------------------------

func TestIPCReadLengthZero(t *testing.T) {
	var buf bytes.Buffer
	ipcutil.Write(&buf, []byte{})
	got, err := ipcutil.Read(&buf)
	if err != nil {
		t.Fatalf("Read empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(got))
	}
}

func TestIPCReadExactMaxSize(t *testing.T) {
	// length = MaxMessageSize (1MB) — exactly at boundary
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(ipcutil.MaxMessageSize))
	buf.Write(make([]byte, ipcutil.MaxMessageSize))

	got, err := ipcutil.Read(&buf)
	if err != nil {
		t.Fatalf("Read at max: %v", err)
	}
	if len(got) != ipcutil.MaxMessageSize {
		t.Fatalf("expected %d bytes, got %d", ipcutil.MaxMessageSize, len(got))
	}
}

func TestIPCReadOverMaxSize(t *testing.T) {
	// length = MaxMessageSize + 1 — should be rejected
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(ipcutil.MaxMessageSize+1))

	_, err := ipcutil.Read(&buf)
	if err == nil {
		t.Fatal("expected error for message > MaxMessageSize")
	}
}

func TestIPCReadMaxUint32(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(0xFFFFFFFF))

	_, err := ipcutil.Read(&buf)
	if err == nil {
		t.Fatal("expected error for max uint32 length")
	}
}

func TestIPCReadTruncatedLengthPrefix(t *testing.T) {
	// Only 3 bytes — can't read full length prefix
	for i := 0; i < 4; i++ {
		r := bytes.NewReader(make([]byte, i))
		_, err := ipcutil.Read(r)
		if err == nil {
			t.Fatalf("expected error for %d-byte length prefix", i)
		}
	}
}

func TestIPCReadTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(100)) // claims 100 bytes
	buf.Write([]byte("short"))                         // only 5 bytes

	_, err := ipcutil.Read(&buf)
	if err == nil {
		t.Fatal("expected error for truncated payload")
	}
}

func TestIPCRoundTripBinaryWithNulls(t *testing.T) {
	data := []byte{0x00, 0x01, 0x00, 0xFF, 0x00}
	var buf bytes.Buffer
	if err := ipcutil.Write(&buf, data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := ipcutil.Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("binary data with nulls mismatch")
	}
}

func TestIPCRoundTripEmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := ipcutil.Write(&buf, nil); err != nil {
		t.Fatalf("Write nil: %v", err)
	}
	got, err := ipcutil.Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 bytes, got %d", len(got))
	}
}

func TestIPCConcurrentWrite(t *testing.T) {
	// Test that concurrent writes to a mutex-protected writer produce
	// valid framing. ipcutil.Write is NOT safe for concurrent use on the
	// same writer (it does two separate writes: length + payload). This
	// test verifies that when callers serialize via a mutex, framing is intact.
	var buf bytes.Buffer
	var mu sync.Mutex

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id int) {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte(id)}, 10)
			mu.Lock()
			ipcutil.Write(&buf, data)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// Read back all messages
	for i := 0; i < n; i++ {
		msg, err := ipcutil.Read(&buf)
		if err != nil {
			t.Fatalf("Read[%d]: %v", i, err)
		}
		if len(msg) != 10 {
			t.Fatalf("message[%d] length: %d != 10", i, len(msg))
		}
		// Each message should be all the same byte
		for _, b := range msg {
			if b != msg[0] {
				t.Fatalf("message[%d] not uniform", i)
			}
		}
	}
}

func TestIPCSequentialMessages(t *testing.T) {
	var buf bytes.Buffer
	messages := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
		{},
		[]byte("fifth"),
	}
	for _, m := range messages {
		if err := ipcutil.Write(&buf, m); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	for i, want := range messages {
		got, err := ipcutil.Read(&buf)
		if err != nil {
			t.Fatalf("Read[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message[%d] mismatch: %q != %q", i, got, want)
		}
	}
}
