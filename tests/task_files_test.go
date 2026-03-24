package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// taskTestCleanup creates temp task dirs and returns a cleanup func.
func taskTestCleanup(t *testing.T) func() {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("get home dir: %v", err)
	}
	tasksDir := filepath.Join(home, ".pilot", "tasks")
	os.MkdirAll(filepath.Join(tasksDir, "submitted"), 0700)
	os.MkdirAll(filepath.Join(tasksDir, "received"), 0700)
	return func() {
		// Clean up test files only (prefixed with test-)
	}
}

func removeTaskFile(taskID string, isSubmitter bool) {
	home, _ := os.UserHomeDir()
	subdir := "received"
	if isSubmitter {
		subdir = "submitted"
	}
	os.Remove(filepath.Join(home, ".pilot", "tasks", subdir, taskID+".json"))
}

// TestSaveAndLoadTaskFile tests SaveTaskFile + LoadTaskFile round-trip.
func TestSaveAndLoadTaskFile(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-save-load-recv"
	defer removeTaskFile(taskID, false)

	tf := tasksubmit.NewTaskFile(taskID, "Test save and load", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, false); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.TaskID != taskID {
		t.Errorf("expected task_id %q, got %q", taskID, loaded.TaskID)
	}
	if loaded.TaskDescription != "Test save and load" {
		t.Errorf("expected description %q, got %q", "Test save and load", loaded.TaskDescription)
	}
	if loaded.Status != tasksubmit.TaskStatusNew {
		t.Errorf("expected status NEW, got %q", loaded.Status)
	}
	if loaded.From != "0:0000.0000.0001" {
		t.Errorf("expected from addr, got %q", loaded.From)
	}
}

// TestSaveAndLoadSubmittedTaskFile tests SaveTaskFile(submitter) + LoadSubmittedTaskFile.
func TestSaveAndLoadSubmittedTaskFile(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-save-load-submit"
	defer removeTaskFile(taskID, true)

	tf := tasksubmit.NewTaskFile(taskID, "Test submitted", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, true); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := daemon.LoadSubmittedTaskFile(taskID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.TaskID != taskID {
		t.Errorf("expected task_id %q, got %q", taskID, loaded.TaskID)
	}
	if loaded.TaskDescription != "Test submitted" {
		t.Errorf("expected description, got %q", loaded.TaskDescription)
	}
}

// TestLoadTaskFileNotFound tests that loading a non-existent file returns an error.
func TestLoadTaskFileNotFound(t *testing.T) {
	t.Parallel()
	_, err := daemon.LoadTaskFile("nonexistent-task-id-xyz")
	if err == nil {
		t.Fatal("expected error loading non-existent task file")
	}
}

// TestUpdateTaskStatus tests UpdateTaskStatus changes the status of a saved file.
func TestUpdateTaskStatus(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-update-status"
	defer removeTaskFile(taskID, false)

	// Create initial task file
	tf := tasksubmit.NewTaskFile(taskID, "Status update test", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, false); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Update status to ACCEPTED
	if err := daemon.UpdateTaskStatus(taskID, tasksubmit.TaskStatusAccepted, "Test accepted", false); err != nil {
		t.Fatalf("update status: %v", err)
	}

	loaded, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load after update: %v", err)
	}

	if loaded.Status != tasksubmit.TaskStatusAccepted {
		t.Errorf("expected ACCEPTED, got %q", loaded.Status)
	}
	if loaded.StatusJustification != "Test accepted" {
		t.Errorf("expected justification, got %q", loaded.StatusJustification)
	}
}

// TestUpdateTaskFileWithTimes tests UpdateTaskFileWithTimes with various actions.
func TestUpdateTaskFileWithTimes(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-update-times"
	defer removeTaskFile(taskID, false)

	// Create task with known creation time
	tf := tasksubmit.NewTaskFile(taskID, "Time update test", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, false); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Accept action — calculates time_idle
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusAccepted, "Accepted", "accept", false, ""); err != nil {
		t.Fatalf("update with accept: %v", err)
	}

	loaded, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load after accept: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusAccepted {
		t.Errorf("expected ACCEPTED, got %q", loaded.Status)
	}
	if loaded.AcceptedAt == "" {
		t.Error("expected accepted_at to be set")
	}

	// Execute action — calculates time_staged
	stagedAt := time.Now().UTC().Format(time.RFC3339)
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusExecuting, "Executing", "execute", false, stagedAt); err != nil {
		t.Fatalf("update with execute: %v", err)
	}

	loaded, err = daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load after execute: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusExecuting {
		t.Errorf("expected EXECUTING, got %q", loaded.Status)
	}
	if loaded.ExecuteStartedAt == "" {
		t.Error("expected execute_started_at to be set")
	}

	// Complete action — calculates time_cpu
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusCompleted, "Done", "complete", false, ""); err != nil {
		t.Fatalf("update with complete: %v", err)
	}

	loaded, err = daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load after complete: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusCompleted {
		t.Errorf("expected COMPLETED, got %q", loaded.Status)
	}
	if loaded.CompletedAt == "" {
		t.Error("expected completed_at to be set")
	}
}

// TestUpdateTaskFileWithTimesExpire tests the "expire" action.
func TestUpdateTaskFileWithTimesExpire(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-update-expire"
	defer removeTaskFile(taskID, false)

	tf := tasksubmit.NewTaskFile(taskID, "Expire test", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, false); err != nil {
		t.Fatalf("save: %v", err)
	}

	stagedAt := time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339)
	if err := daemon.UpdateTaskFileWithTimes(taskID, tasksubmit.TaskStatusExpired, "Expired", "expire", false, stagedAt); err != nil {
		t.Fatalf("update with expire: %v", err)
	}

	loaded, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusExpired {
		t.Errorf("expected EXPIRED, got %q", loaded.Status)
	}
	if loaded.StagedAt == "" {
		t.Error("expected staged_at to be set for expire action")
	}
}

// TestCancelTaskBothSides tests CancelTaskBothSides writes to both directories.
func TestCancelTaskBothSides(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-cancel-both"
	defer removeTaskFile(taskID, false)
	defer removeTaskFile(taskID, true)

	// Create task on both sides
	tf := tasksubmit.NewTaskFile(taskID, "Cancel both test", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, false); err != nil {
		t.Fatalf("save receiver: %v", err)
	}
	if err := daemon.SaveTaskFile(tf, true); err != nil {
		t.Fatalf("save submitter: %v", err)
	}

	// Cancel both sides
	if err := daemon.CancelTaskBothSides(taskID); err != nil {
		t.Fatalf("cancel both sides: %v", err)
	}

	// Verify receiver side
	loaded, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load receiver: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusCancelled {
		t.Errorf("receiver: expected CANCELLED, got %q", loaded.Status)
	}

	// Verify submitter side
	loadedSub, err := daemon.LoadSubmittedTaskFile(taskID)
	if err != nil {
		t.Fatalf("load submitter: %v", err)
	}
	if loadedSub.Status != tasksubmit.TaskStatusCancelled {
		t.Errorf("submitter: expected CANCELLED, got %q", loadedSub.Status)
	}
}

// TestExpireTaskBothSides tests ExpireTaskBothSides with nil registry.
func TestExpireTaskBothSides(t *testing.T) {
	t.Parallel()
	cleanup := taskTestCleanup(t)
	defer cleanup()

	taskID := "test-expire-both"
	defer removeTaskFile(taskID, false)
	defer removeTaskFile(taskID, true)

	tf := tasksubmit.NewTaskFile(taskID, "Expire both test", "0:0000.0000.0001", "0:0000.0000.0002")
	if err := daemon.SaveTaskFile(tf, false); err != nil {
		t.Fatalf("save receiver: %v", err)
	}
	if err := daemon.SaveTaskFile(tf, true); err != nil {
		t.Fatalf("save submitter: %v", err)
	}

	stagedAt := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	// Pass nil registry — should still update files
	if err := daemon.ExpireTaskBothSides(taskID, stagedAt, nil, 0); err != nil {
		t.Fatalf("expire both sides: %v", err)
	}

	loaded, err := daemon.LoadTaskFile(taskID)
	if err != nil {
		t.Fatalf("load receiver: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusExpired {
		t.Errorf("receiver: expected EXPIRED, got %q", loaded.Status)
	}

	loadedSub, err := daemon.LoadSubmittedTaskFile(taskID)
	if err != nil {
		t.Fatalf("load submitter: %v", err)
	}
	if loadedSub.Status != tasksubmit.TaskStatusExpired {
		t.Errorf("submitter: expected EXPIRED, got %q", loadedSub.Status)
	}
}

// TestRemoveFromQueue tests the package-level RemoveFromQueue function.
func TestRemoveFromQueue(t *testing.T) {
	t.Parallel()
	// RemoveFromQueue operates on the global queue — removing non-existent is fine
	removed := daemon.RemoveFromQueue("nonexistent-task-123")
	if removed {
		t.Error("expected false for non-existent task")
	}
}

// TestGetQueueStagedAt tests the package-level GetQueueStagedAt function.
func TestGetQueueStagedAt(t *testing.T) {
	t.Parallel()
	stagedAt := daemon.GetQueueStagedAt("nonexistent-task-456")
	if stagedAt != "" {
		t.Errorf("expected empty staged_at for non-existent task, got %q", stagedAt)
	}
}
