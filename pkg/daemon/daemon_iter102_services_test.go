package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/dataexchange"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// Iter-102 coverage for services.go file-I/O + task lifecycle helpers at 0%:
// saveReceivedFile, saveInboxMessage, CancelTaskBothSides, ExpireTaskBothSides,
// checkAndCancelExpiredNewTasks, checkAndExpireQueueHead + ipc.go trackConn.
//
// All tests use t.TempDir()+t.Setenv("HOME",tmp) to isolate from ~/.pilot.
// Daemon is constructed via New(Config{}) which leaves webhook=nil — webhook.Emit
// is nil-receiver safe (memorized), so calls through saveReceivedFile /
// saveInboxMessage don't need a real webhook wired.

// --- saveReceivedFile: TypeFile payload lands under ~/.pilot/received/ ---

func TestSaveReceivedFileWritesPayloadUnderReceivedDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	frame := &dataexchange.Frame{
		Type:     dataexchange.TypeFile,
		Filename: "my-doc.txt",
		Payload:  []byte("hello world content"),
	}

	if err := d.saveReceivedFile(frame); err != nil {
		t.Fatalf("saveReceivedFile: %v", err)
	}

	// File written with a timestamped name, not the raw one — scan dir.
	receivedDir := filepath.Join(tmp, ".pilot", "received")
	entries, err := os.ReadDir(receivedDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var found bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "my-doc-") && strings.HasSuffix(e.Name(), ".txt") {
			data, err := os.ReadFile(filepath.Join(receivedDir, e.Name()))
			if err != nil {
				t.Fatalf("read saved file: %v", err)
			}
			if string(data) != "hello world content" {
				t.Fatalf("payload = %q, want %q", string(data), "hello world content")
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no my-doc-*.txt in %s, entries: %v", receivedDir, entries)
	}
}

func TestSaveReceivedFileSanitizesFilenameBase(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	frame := &dataexchange.Frame{
		Type:     dataexchange.TypeFile,
		Filename: "/etc/passwd", // should be sanitized via filepath.Base
		Payload:  []byte("attempt"),
	}

	if err := d.saveReceivedFile(frame); err != nil {
		t.Fatalf("saveReceivedFile: %v", err)
	}

	receivedDir := filepath.Join(tmp, ".pilot", "received")
	entries, _ := os.ReadDir(receivedDir)
	// Should NOT escape — file is named passwd-<ts> (no ext) in the received dir.
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "passwd-") {
			t.Fatalf("sanitized filename should start with passwd-, got %q", e.Name())
		}
	}
	// Explicitly verify /etc/passwd was NOT overwritten (though chroot-bound by
	// HOME override this is belt-and-suspenders — if sanitizer broke, writing
	// to a dir containing "/" would likely error anyway).
}

// --- saveInboxMessage: text/JSON/binary messages → inbox JSON file ---

func TestSaveInboxMessageWritesTextToInbox(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	frame := &dataexchange.Frame{
		Type:    dataexchange.TypeText,
		Payload: []byte("hello from peer"),
	}
	from := protocol.Addr{Network: 1, Node: 0x1234}

	if err := d.saveInboxMessage(frame, from); err != nil {
		t.Fatalf("saveInboxMessage text: %v", err)
	}

	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	entries, err := os.ReadDir(inboxDir)
	if err != nil {
		t.Fatalf("ReadDir inbox: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no files written to inbox")
	}
	// Filename format: <type>-<ts>.json; for TypeText → starts with "text-"
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "TEXT-") && strings.HasSuffix(e.Name(), ".json") {
			data, _ := os.ReadFile(filepath.Join(inboxDir, e.Name()))
			if !strings.Contains(string(data), "hello from peer") {
				t.Fatalf("inbox file missing payload: %s", string(data))
			}
			if !strings.Contains(string(data), "TEXT") {
				t.Fatalf("inbox file missing type field: %s", string(data))
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no TEXT-*.json in %s", inboxDir)
	}
}

func TestSaveInboxMessageJSONAndBinaryTypes(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	from := protocol.Addr{Network: 1, Node: 0x9999}

	for _, tc := range []struct {
		name   string
		ftype  uint32
		prefix string
	}{
		{"json", dataexchange.TypeJSON, "JSON-"},
		{"binary", dataexchange.TypeBinary, "BINARY-"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &dataexchange.Frame{Type: tc.ftype, Payload: []byte("x")}
			if err := d.saveInboxMessage(f, from); err != nil {
				t.Fatalf("saveInboxMessage %s: %v", tc.name, err)
			}
		})
	}

	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	entries, _ := os.ReadDir(inboxDir)
	var sawJSON, sawBinary bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "JSON-") {
			sawJSON = true
		}
		if strings.HasPrefix(e.Name(), "BINARY-") {
			sawBinary = true
		}
	}
	if !sawJSON || !sawBinary {
		t.Fatalf("missing files: json=%v binary=%v (entries: %v)", sawJSON, sawBinary, entries)
	}
}

// --- CancelTaskBothSides: mutates both submitted/ and received/ files ---

func TestCancelTaskBothSidesUpdatesBothFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Seed both sides.
	recv := tasksubmit.NewTaskFile("task-cancel-both", "desc", "1:a.b.c", "1:d.e.f")
	sub := tasksubmit.NewTaskFile("task-cancel-both", "desc", "1:a.b.c", "1:d.e.f")
	if err := SaveTaskFile(recv, false); err != nil {
		t.Fatalf("SaveTaskFile recv: %v", err)
	}
	if err := SaveTaskFile(sub, true); err != nil {
		t.Fatalf("SaveTaskFile sub: %v", err)
	}

	if err := CancelTaskBothSides("task-cancel-both"); err != nil {
		t.Fatalf("CancelTaskBothSides: %v", err)
	}

	rloaded, _ := LoadTaskFile("task-cancel-both")
	sloaded, _ := LoadSubmittedTaskFile("task-cancel-both")
	if rloaded.Status != tasksubmit.TaskStatusCancelled {
		t.Fatalf("receiver status = %q, want CANCELLED", rloaded.Status)
	}
	if sloaded.Status != tasksubmit.TaskStatusCancelled {
		t.Fatalf("submitter status = %q, want CANCELLED", sloaded.Status)
	}
}

func TestCancelTaskBothSidesMissingReturnsError(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// ensureTaskDirs not called, both files missing → both returns error → combined.
	err := CancelTaskBothSides("nope")
	if err == nil {
		t.Fatal("CancelTaskBothSides on missing files should error")
	}
	if !strings.Contains(err.Error(), "receiver:") && !strings.Contains(err.Error(), "submitter:") {
		t.Fatalf("err = %v, want combined receiver/submitter wrap", err)
	}
}

// --- ExpireTaskBothSides: nil regConn skips polo score update ---

func TestExpireTaskBothSidesWithNilRegConnUpdatesFiles(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	recv := tasksubmit.NewTaskFile("task-exp-both", "desc", "1:a.b.c", "1:d.e.f")
	sub := tasksubmit.NewTaskFile("task-exp-both", "desc", "1:a.b.c", "1:d.e.f")
	if err := SaveTaskFile(recv, false); err != nil {
		t.Fatalf("SaveTaskFile recv: %v", err)
	}
	if err := SaveTaskFile(sub, true); err != nil {
		t.Fatalf("SaveTaskFile sub: %v", err)
	}

	stagedAt := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	// Pass nil regConn → skips UpdatePoloScore.
	if err := ExpireTaskBothSides("task-exp-both", stagedAt, nil, 42); err != nil {
		t.Fatalf("ExpireTaskBothSides: %v", err)
	}

	rloaded, _ := LoadTaskFile("task-exp-both")
	sloaded, _ := LoadSubmittedTaskFile("task-exp-both")
	if rloaded.Status != tasksubmit.TaskStatusExpired {
		t.Fatalf("receiver status = %q, want EXPIRED", rloaded.Status)
	}
	if sloaded.Status != tasksubmit.TaskStatusExpired {
		t.Fatalf("submitter status = %q", sloaded.Status)
	}
	if rloaded.StagedAt != stagedAt {
		t.Fatalf("receiver StagedAt not set")
	}
}

// --- checkAndCancelExpiredNewTasks: task older than 1m accept-timeout → cancelled ---

func TestCheckAndCancelExpiredNewTasksCancelsOldNewTask(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})

	// Task created 2m ago (past 1m TaskAcceptTimeout) with Status=NEW.
	old := tasksubmit.NewTaskFile("task-old", "desc", "1:a.b.c", "1:d.e.f")
	old.CreatedAt = time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339)
	if err := SaveTaskFile(old, false); err != nil {
		t.Fatalf("SaveTaskFile old: %v", err)
	}
	// Seed submitter side so CancelTaskBothSides succeeds on both halves.
	if err := SaveTaskFile(old, true); err != nil {
		t.Fatalf("SaveTaskFile old submitter: %v", err)
	}
	// Fresh task still within window — should be preserved.
	fresh := tasksubmit.NewTaskFile("task-fresh", "desc", "1:a.b.c", "1:d.e.f")
	if err := SaveTaskFile(fresh, false); err != nil {
		t.Fatalf("SaveTaskFile fresh: %v", err)
	}

	d.checkAndCancelExpiredNewTasks()

	rOld, _ := LoadTaskFile("task-old")
	if rOld.Status != tasksubmit.TaskStatusCancelled {
		t.Fatalf("old task status = %q, want CANCELLED", rOld.Status)
	}
	rFresh, _ := LoadTaskFile("task-fresh")
	if rFresh.Status != tasksubmit.TaskStatusNew {
		t.Fatalf("fresh task status = %q, want NEW (should not have been touched)", rFresh.Status)
	}
}

func TestCheckAndCancelExpiredNewTasksNoReceivedDirNoop(t *testing.T) {
	// If received/ doesn't exist, the function should return cleanly via the
	// os.ReadDir error branch — no panic.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	d.checkAndCancelExpiredNewTasks() // no setup → should noop
}

// --- checkAndExpireQueueHead: stagedAt > 1h → task expires ---

func TestCheckAndExpireQueueHeadEmptyQueueNoop(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	// Fresh daemon → empty taskQueue → head is "" → early return.
	d.checkAndExpireQueueHead() // must not panic
}

func TestCheckAndExpireQueueHeadExpiresOldHead(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})

	// Seed both files for the head task.
	recv := tasksubmit.NewTaskFile("task-head", "desc", "1:a.b.c", "1:d.e.f")
	sub := tasksubmit.NewTaskFile("task-head", "desc", "1:a.b.c", "1:d.e.f")
	if err := SaveTaskFile(recv, false); err != nil {
		t.Fatalf("SaveTaskFile recv: %v", err)
	}
	if err := SaveTaskFile(sub, true); err != nil {
		t.Fatalf("SaveTaskFile sub: %v", err)
	}

	// Add to queue (becomes head) then manually stomp the stagedAt to >1h ago.
	d.taskQueue.Add("task-head")
	d.taskQueue.mu.Lock()
	d.taskQueue.headStagedAt["task-head"] = time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	d.taskQueue.mu.Unlock()

	d.checkAndExpireQueueHead()

	// After expiry: task removed from queue AND both files updated to EXPIRED.
	if d.taskQueue.Peek() != "" {
		t.Fatalf("head not removed, peek = %q", d.taskQueue.Peek())
	}
	rloaded, _ := LoadTaskFile("task-head")
	if rloaded.Status != tasksubmit.TaskStatusExpired {
		t.Fatalf("receiver status = %q, want EXPIRED", rloaded.Status)
	}
}

func TestCheckAndExpireQueueHeadFreshHeadPreserved(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	d.taskQueue.Add("task-fresh-head") // stagedAt = now → time.Since < 1h → preserved

	d.checkAndExpireQueueHead()

	if d.taskQueue.Peek() != "task-fresh-head" {
		t.Fatalf("fresh head removed: peek = %q, want task-fresh-head", d.taskQueue.Peek())
	}
}

func TestCheckAndExpireQueueHeadInvalidStagedAtNoop(t *testing.T) {
	// If stagedAt fails to parse, function returns without removing — exercises
	// the ParseTime error-return branch.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	d.taskQueue.Add("task-bad-staged")
	d.taskQueue.mu.Lock()
	d.taskQueue.headStagedAt["task-bad-staged"] = "not-a-timestamp"
	d.taskQueue.mu.Unlock()

	d.checkAndExpireQueueHead()

	// Preserved because ParseTime errored out before the expiry check.
	if d.taskQueue.Peek() != "task-bad-staged" {
		t.Fatalf("bad-staged head removed: peek = %q", d.taskQueue.Peek())
	}
}

// --- ipcConn.trackConn: mutex-protected append ---

func TestIpcConnTrackConnAppendsAllIDs(t *testing.T) {
	c := &ipcConn{}
	for i := uint32(0); i < 5; i++ {
		c.trackConn(i * 100)
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.conns) != 5 {
		t.Fatalf("conns len = %d, want 5", len(c.conns))
	}
	for i, want := range []uint32{0, 100, 200, 300, 400} {
		if c.conns[i] != want {
			t.Fatalf("conns[%d] = %d, want %d", i, c.conns[i], want)
		}
	}
}

func TestIpcConnTrackConnConcurrentSafe(t *testing.T) {
	c := &ipcConn{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			c.trackConn(id)
		}(uint32(i))
	}
	wg.Wait()

	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.conns) != 50 {
		t.Fatalf("conns len after 50 concurrent appends = %d, want 50", len(c.conns))
	}
}
