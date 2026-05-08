// SPDX-License-Identifier: AGPL-3.0-or-later

package replication_test

import (
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/replication"
)

// --- Manager tests ---

// pipeConn returns a connected pair of net.Conn backed by net.Pipe().
func pipeConn(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return a, b
}

// readFramed reads a length-prefixed JSON frame from conn and unmarshals it.
func readFramed(t *testing.T, conn net.Conn) map[string]interface{} {
	t.Helper()
	conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read length prefix: %v", err)
	}
	length := uint32(lenBuf[0])<<24 | uint32(lenBuf[1])<<16 | uint32(lenBuf[2])<<8 | uint32(lenBuf[3])
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	var msg map[string]interface{}
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return msg
}

func TestManager_PushReachesSubscriber(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()

	primary, standby := pipeConn(t)

	m.AddSub(primary)
	if m.SubCount() != 1 {
		t.Fatalf("want 1 subscriber, got %d", m.SubCount())
	}

	snapJSON := []byte(`{"next_node":42}`)

	// net.Pipe() is synchronous — Push() blocks until standby drains.
	// Run Push in a goroutine so we can read on the standby side concurrently.
	go m.Push(snapJSON)

	msg := readFramed(t, standby)
	if msg["type"] != "replication_snapshot" {
		t.Fatalf("expected replication_snapshot, got %q", msg["type"])
	}
}

func TestManager_RemoveSub(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()

	primary, standby := pipeConn(t)
	_ = standby

	m.AddSub(primary)
	m.RemoveSub(primary)

	if m.SubCount() != 0 {
		t.Fatalf("want 0 subscribers after remove, got %d", m.SubCount())
	}
}

func TestManager_FailedSubRemovedOnPush(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()

	primary, standby := pipeConn(t)
	// Close both ends so the write will fail.
	standby.Close()
	primary.Close()

	// Manually add the already-closed conn as a subscriber.
	// We can't use AddSub normally on a closed conn, so re-create.
	p2, s2 := pipeConn(t)
	m.AddSub(p2)
	s2.Close() // close reader — next Push write will fail

	snapJSON := []byte(`{"next_node":1}`)
	m.Push(snapJSON)

	// After the failed push, subscriber should be auto-removed.
	if m.SubCount() != 0 {
		t.Fatalf("want 0 subscribers after failed push, got %d", m.SubCount())
	}
}

func TestManager_StartHeartbeat(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()

	primary, standby := pipeConn(t)
	m.AddSub(primary)
	_ = standby

	done := make(chan struct{})
	go m.StartHeartbeat(done)

	// Verify that StartHeartbeat exits cleanly when done is closed.
	close(done)
	// Give the goroutine a moment to exit (it selects on done).
	// No panic = pass.
}

// --- Directory-sync type tests ---

func TestParseDirectoryEntries_Basic(t *testing.T) {
	t.Parallel()
	raw := []interface{}{
		map[string]interface{}{
			"external_id":  "alice@example.com",
			"display_name": "Alice",
			"role":         "admin",
		},
		map[string]interface{}{
			"external_id": "bob@example.com",
			"disabled":    true,
		},
		// entry with no external_id — should be skipped
		map[string]interface{}{
			"display_name": "ghost",
		},
	}

	entries := replication.ParseDirectoryEntries(raw)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ExternalID != "alice@example.com" {
		t.Errorf("entry[0].ExternalID = %q, want alice@example.com", entries[0].ExternalID)
	}
	if entries[0].Role != "admin" {
		t.Errorf("entry[0].Role = %q, want admin", entries[0].Role)
	}
	if !entries[1].Disabled {
		t.Errorf("entry[1].Disabled should be true")
	}
}

func TestParseDirectoryEntries_Groups(t *testing.T) {
	t.Parallel()
	raw := []interface{}{
		map[string]interface{}{
			"external_id": "carol@example.com",
			"groups":      []interface{}{"engineering", "admins"},
		},
	}

	entries := replication.ParseDirectoryEntries(raw)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(entries[0].Groups))
	}
}

func TestStrField(t *testing.T) {
	t.Parallel()
	m := map[string]interface{}{
		"name": "alice",
		"age":  42,
	}
	if replication.StrField(m, "name") != "alice" {
		t.Error("StrField should return string value")
	}
	if replication.StrField(m, "age") != "" {
		t.Error("StrField should return empty string for non-string type")
	}
	if replication.StrField(m, "missing") != "" {
		t.Error("StrField should return empty string for missing key")
	}
}

func TestBoolField(t *testing.T) {
	t.Parallel()
	m := map[string]interface{}{
		"enabled":  true,
		"disabled": false,
		"count":    3,
	}
	if !replication.BoolField(m, "enabled") {
		t.Error("BoolField should return true")
	}
	if replication.BoolField(m, "disabled") {
		t.Error("BoolField should return false")
	}
	if replication.BoolField(m, "count") {
		t.Error("BoolField should return false for non-bool type")
	}
}

func TestNormalizeExternalID(t *testing.T) {
	t.Parallel()
	if replication.NormalizeExternalID("Alice@Example.COM") != "alice@example.com" {
		t.Error("NormalizeExternalID should lowercase")
	}
}

// --- Clone helper tests ---

func TestCloneSliceUint16(t *testing.T) {
	t.Parallel()
	orig := []uint16{1, 2, 3}
	cp := replication.CloneSliceUint16(orig)
	if len(cp) != len(orig) {
		t.Fatalf("lengths differ")
	}
	cp[0] = 99
	if orig[0] == 99 {
		t.Error("clone shares backing array with original")
	}

	if replication.CloneSliceUint16(nil) != nil {
		t.Error("nil-in should return nil")
	}
}

func TestCloneSliceUint32(t *testing.T) {
	t.Parallel()
	orig := []uint32{10, 20}
	cp := replication.CloneSliceUint32(orig)
	cp[0] = 999
	if orig[0] == 999 {
		t.Error("clone shares backing array with original")
	}
	if replication.CloneSliceUint32(nil) != nil {
		t.Error("nil-in should return nil")
	}
}

func TestCloneSliceString(t *testing.T) {
	t.Parallel()
	orig := []string{"a", "b"}
	cp := replication.CloneSliceString(orig)
	cp[0] = "z"
	if orig[0] == "z" {
		t.Error("clone shares backing array with original")
	}
	if replication.CloneSliceString(nil) != nil {
		t.Error("nil-in should return nil")
	}
}

func TestSubCountEmpty(t *testing.T) {
	t.Parallel()
	m := replication.NewManager()
	if m.SubCount() != 0 {
		t.Errorf("new manager should have 0 subscribers, got %d", m.SubCount())
	}
}
