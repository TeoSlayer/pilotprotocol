package responder_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/automations/responder"
)

func TestParseRequest_Valid(t *testing.T) {
	msg := &responder.InboxMessage{
		Data: `{"command":"polymarket","body":"from: 2026-04-02T00:00:00Z"}`,
	}
	req, err := msg.ParseRequest()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Command != "polymarket" {
		t.Errorf("Command = %q, want %q", req.Command, "polymarket")
	}
	if req.Body != "from: 2026-04-02T00:00:00Z" {
		t.Errorf("Body = %q", req.Body)
	}
}

func TestParseRequest_InvalidJSON(t *testing.T) {
	msg := &responder.InboxMessage{Data: "not json"}
	_, err := msg.ParseRequest()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseRequest_MissingCommand(t *testing.T) {
	msg := &responder.InboxMessage{Data: `{"body":"some body"}`}
	_, err := msg.ParseRequest()
	if err == nil {
		t.Fatal("expected error for missing command field")
	}
}

func TestParseRequest_EmptyData(t *testing.T) {
	msg := &responder.InboxMessage{Data: ""}
	_, err := msg.ParseRequest()
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestReadInboxFrom_ReadsAndSkipsBadFiles(t *testing.T) {
	dir := t.TempDir()

	writeInboxFile(t, dir, "msg1.json", responder.InboxMessage{
		Type: "JSON",
		From: "0:0000.0000.0001",
		Data: `{"command":"stockmarket","body":"from: 2026-04-01"}`,
	})
	// Bad JSON — should be silently skipped.
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	writeInboxFile(t, dir, "msg2.json", responder.InboxMessage{
		Type: "TEXT",
		From: "0:0000.0000.0002",
		Data: `{"command":"polymarket","body":"from: 2026-04-02T00:00:00Z"}`,
	})

	msgs, err := responder.ReadInboxFrom(dir)
	if err != nil {
		t.Fatalf("ReadInboxFrom: %v", err)
	}
	if len(msgs) != 2 {
		t.Errorf("expected 2 valid messages, got %d", len(msgs))
	}
}

func TestReadInboxFrom_EmptyDir(t *testing.T) {
	msgs, err := responder.ReadInboxFrom(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestReadInboxFrom_MissingDir(t *testing.T) {
	msgs, err := responder.ReadInboxFrom(filepath.Join(t.TempDir(), "nonexistent"))
	if err != nil {
		t.Fatalf("missing dir should return nil, nil; got err: %v", err)
	}
	if msgs != nil {
		t.Errorf("expected nil messages for missing dir")
	}
}

func TestInboxMessage_Delete(t *testing.T) {
	dir := t.TempDir()
	writeInboxFile(t, dir, "to_delete.json", responder.InboxMessage{
		Type: "TEXT",
		From: "0:0000.0000.0001",
		Data: `{"command":"ping","body":""}`,
	})

	// Use ReadInboxFrom so the message has its internal filePath set.
	msgs, err := responder.ReadInboxFrom(dir)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("setup: got %v msgs, err: %v", len(msgs), err)
	}

	if err := msgs[0].Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	remaining, _ := responder.ReadInboxFrom(dir)
	if len(remaining) != 0 {
		t.Errorf("expected inbox to be empty after Delete, got %d message(s)", len(remaining))
	}
}

// writeInboxFile marshals msg as JSON and writes it to dir/name.
func writeInboxFile(t *testing.T, dir, name string, msg responder.InboxMessage) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
