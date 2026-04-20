package daemon

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/internal/crypto"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// Iter-107 coverage for handleTaskSubmitRequest (0% baseline) — the polo-gated
// submitter→receiver request path on port 1003. Needs a real registry to call
// GetPoloScore(submitter) and GetPoloScore(receiver), plus signer wiring. The
// response-write path fails cleanly because the test Connection's State=0 (not
// Established) causes SendData to return early before any tunnel interaction.

// registerPeer registers a new identity with the test registry and returns
// its nodeID. Tests use this to get a valid submitter-node for the polo check.
func registerPeer(t *testing.T, d *Daemon) uint32 {
	t.Helper()
	peerID, _ := crypto.GenerateIdentity()
	resp, err := d.regConn.RegisterWithKey("127.0.0.1:0", crypto.EncodePublicKey(peerID.PublicKey), "", nil)
	if err != nil {
		t.Fatalf("register peer: %v", err)
	}
	return uint32(resp["node_id"].(float64))
}

// --- accepted path: submitter polo >= receiver polo → task persisted + queued ---

func TestHandleTaskSubmitRequestAcceptedWhenPoloOK(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(c string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(c)))
	})

	peerNodeID := registerPeer(t, d)

	// Set polos: submitter=10, receiver=5 → submitter >= receiver → accept
	if _, err := d.regConn.SetPoloScore(peerNodeID, 10); err != nil {
		t.Fatalf("set submitter polo: %v", err)
	}
	if _, err := d.regConn.SetPoloScore(d.NodeID(), 5); err != nil {
		t.Fatalf("set receiver polo: %v", err)
	}

	req := &tasksubmit.SubmitRequest{
		TaskID:          "task-polo-accept",
		TaskDescription: "test work",
		FromAddr:        "1:0001.0000.0001",
		ToAddr:          "1:0001.0000.0002",
	}
	frame, _ := tasksubmit.MarshalSubmitRequest(req)

	conn := &Connection{
		RecvBuf:    make(chan []byte, 4),
		RemoteAddr: protocol.Addr{Node: peerNodeID},
	}
	adapter := newConnAdapter(d, conn)

	// Response WriteFrame will fail because conn.State=0 (not Established)
	// — that's logged and swallowed; we assert on persisted state only.
	d.handleTaskSubmitRequest(adapter, conn, frame)

	// Task file must exist in received/ with status=NEW.
	loaded, err := LoadTaskFile("task-polo-accept")
	if err != nil {
		t.Fatalf("load received task: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusNew {
		t.Fatalf("Status = %q, want NEW", loaded.Status)
	}
	if loaded.TaskDescription != "test work" {
		t.Fatalf("TaskDescription = %q, want 'test work'", loaded.TaskDescription)
	}

	// Task must be queued.
	if head := d.taskQueue.Peek(); head != "task-polo-accept" {
		t.Fatalf("queue head = %q, want 'task-polo-accept'", head)
	}
}

// --- rejected path: submitter polo < receiver polo → no persistence, no queue ---

func TestHandleTaskSubmitRequestRejectedWhenPoloLow(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(c string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(c)))
	})

	peerNodeID := registerPeer(t, d)
	// submitter=3, receiver=10 → polo too low
	if _, err := d.regConn.SetPoloScore(peerNodeID, 3); err != nil {
		t.Fatalf("set submitter polo: %v", err)
	}
	if _, err := d.regConn.SetPoloScore(d.NodeID(), 10); err != nil {
		t.Fatalf("set receiver polo: %v", err)
	}

	req := &tasksubmit.SubmitRequest{
		TaskID:          "task-polo-reject",
		TaskDescription: "should be rejected",
		FromAddr:        "1:0001.0000.0001",
		ToAddr:          "1:0001.0000.0002",
	}
	frame, _ := tasksubmit.MarshalSubmitRequest(req)

	conn := &Connection{
		RecvBuf:    make(chan []byte, 4),
		RemoteAddr: protocol.Addr{Node: peerNodeID},
	}
	adapter := newConnAdapter(d, conn)
	d.handleTaskSubmitRequest(adapter, conn, frame)

	// No task file should exist in received/.
	if _, err := LoadTaskFile("task-polo-reject"); err == nil {
		t.Fatal("received/ task file should NOT exist for rejected submission")
	}
	if head := d.taskQueue.Peek(); head != "" {
		t.Fatalf("queue head = %q, want empty (rejected task must not be queued)", head)
	}
}

// --- no-regConn fail-closed path: accepted=false, no persistence ---

func TestHandleTaskSubmitRequestNoRegConnFailsClosed(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{}) // no regConn

	req := &tasksubmit.SubmitRequest{
		TaskID:          "task-no-reg",
		TaskDescription: "registry unavailable",
		FromAddr:        "1:0001.0000.0001",
		ToAddr:          "1:0001.0000.0002",
	}
	frame, _ := tasksubmit.MarshalSubmitRequest(req)

	conn := &Connection{
		RecvBuf:    make(chan []byte, 4),
		RemoteAddr: protocol.Addr{Node: 1234},
	}
	adapter := newConnAdapter(d, conn)
	d.handleTaskSubmitRequest(adapter, conn, frame)

	if _, err := LoadTaskFile("task-no-reg"); err == nil {
		t.Fatal("received/ task file should NOT exist when regConn is nil (fail-closed)")
	}
	if head := d.taskQueue.Peek(); head != "" {
		t.Fatalf("queue head = %q, want empty (fail-closed must not enqueue)", head)
	}
}

// --- malformed frame (wrong type) → Unmarshal errors, no mutation ---

func TestHandleTaskSubmitRequestMalformedFrameReturnsCleanly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})

	// Frame typed as TypeStatusUpdate (3) — UnmarshalSubmitRequest expects TypeSubmit (1).
	badFrame := &tasksubmit.Frame{Type: tasksubmit.TypeStatusUpdate, Payload: []byte("{}")}

	conn := &Connection{
		RecvBuf:    make(chan []byte, 4),
		RemoteAddr: protocol.Addr{Node: 1234},
	}
	adapter := newConnAdapter(d, conn)
	d.handleTaskSubmitRequest(adapter, conn, badFrame)

	// No received/ dir should have been created (no task file attempted).
	tasksDir, err := getTasksDir()
	if err != nil {
		t.Fatalf("getTasksDir: %v", err)
	}
	receivedDir := filepath.Join(tasksDir, "received")
	entries, _ := os.ReadDir(receivedDir)
	if len(entries) > 0 {
		t.Fatalf("received/ has %d entries; want 0 after malformed frame", len(entries))
	}
	if head := d.taskQueue.Peek(); head != "" {
		t.Fatalf("queue head = %q, want empty", head)
	}
}

// --- polo edge case: submitter == receiver (equal) → still accepted (>=) ---

func TestHandleTaskSubmitRequestEqualPoloAccepts(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := newHsTestDaemon(t, Config{})
	d.regConn.SetSigner(func(c string) string {
		return base64.StdEncoding.EncodeToString(d.identity.Sign([]byte(c)))
	})

	peerNodeID := registerPeer(t, d)
	// submitter=7, receiver=7 → >= true → accept (boundary: equal scores allowed)
	if _, err := d.regConn.SetPoloScore(peerNodeID, 7); err != nil {
		t.Fatalf("set submitter polo: %v", err)
	}
	if _, err := d.regConn.SetPoloScore(d.NodeID(), 7); err != nil {
		t.Fatalf("set receiver polo: %v", err)
	}

	req := &tasksubmit.SubmitRequest{
		TaskID:          "task-polo-equal",
		TaskDescription: "equal scores",
		FromAddr:        "1:0001.0000.0001",
		ToAddr:          "1:0001.0000.0002",
	}
	frame, _ := tasksubmit.MarshalSubmitRequest(req)

	conn := &Connection{
		RecvBuf:    make(chan []byte, 4),
		RemoteAddr: protocol.Addr{Node: peerNodeID},
	}
	adapter := newConnAdapter(d, conn)
	d.handleTaskSubmitRequest(adapter, conn, frame)

	loaded, err := LoadTaskFile("task-polo-equal")
	if err != nil {
		t.Fatalf("equal-polo should accept; LoadTaskFile: %v", err)
	}
	if loaded.TaskID != "task-polo-equal" {
		t.Fatalf("loaded.TaskID = %q, want 'task-polo-equal'", loaded.TaskID)
	}
}
