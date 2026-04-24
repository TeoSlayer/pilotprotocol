// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// Iter-105 coverage for handleTaskStatusUpdate (0% baseline) and
// handleTaskResults (0% baseline) — the inbound task-lifecycle handlers
// that the submitter receives from the executor on port 1003. These run
// AFTER handleTaskSubmitConn has dispatched by frame.Type, so they take
// a decoded frame and mutate on-disk task state under ~/.pilot/tasks/.

// seedSubmittedTaskFile creates a submitted/ task file with NEW status.
func seedSubmittedTaskFile(t *testing.T, taskID string) {
	t.Helper()
	tf := tasksubmit.NewTaskFile(taskID, "test task", "1:0001.0000.0001", "1:0001.0000.0002")
	if err := SaveTaskFile(tf, true); err != nil {
		t.Fatalf("seed submitted task: %v", err)
	}
}

// --- handleTaskStatusUpdate: mutates submitted/ task file Status + Justification ---

func TestHandleTaskStatusUpdateMutatesSubmittedTaskFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	seedSubmittedTaskFile(t, "task-status-update")

	update := &tasksubmit.TaskStatusUpdate{
		TaskID:        "task-status-update",
		Status:        tasksubmit.TaskStatusAccepted,
		Justification: "peer accepted",
	}
	frame, err := tasksubmit.MarshalTaskStatusUpdate(update)
	if err != nil {
		t.Fatalf("marshal update: %v", err)
	}

	d.handleTaskStatusUpdate(nil, nil, frame)

	loaded, err := LoadSubmittedTaskFile("task-status-update")
	if err != nil {
		t.Fatalf("load after update: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusAccepted {
		t.Fatalf("Status = %q, want %q", loaded.Status, tasksubmit.TaskStatusAccepted)
	}
	if loaded.StatusJustification != "peer accepted" {
		t.Fatalf("StatusJustification = %q, want 'peer accepted'", loaded.StatusJustification)
	}
}

// --- handleTaskStatusUpdate: wrong frame type → Unmarshal errors, no mutation ---

func TestHandleTaskStatusUpdateWrongFrameTypeReturnsCleanly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	seedSubmittedTaskFile(t, "task-wrong-type")

	// A SendResults-typed frame should NOT be decodable as a status update.
	badFrame := &tasksubmit.Frame{Type: tasksubmit.TypeSendResults, Payload: []byte("{}")}

	d.handleTaskStatusUpdate(nil, nil, badFrame)

	loaded, _ := LoadSubmittedTaskFile("task-wrong-type")
	if loaded.Status != tasksubmit.TaskStatusNew {
		t.Fatalf("Status = %q, want NEW (no mutation on malformed frame)", loaded.Status)
	}
}

// --- handleTaskResults: text-result path writes <taskID>_result.txt + COMPLETED ---

func TestHandleTaskResultsTextResultSavesAndMarksCompleted(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{}) // no regConn → polo-score path skipped
	seedSubmittedTaskFile(t, "task-text-result")

	msg := &tasksubmit.TaskResultMessage{
		TaskID:      "task-text-result",
		ResultType:  "text",
		ResultText:  "42",
		CompletedAt: "2026-04-20T06:00:00Z",
	}
	frame, err := tasksubmit.MarshalTaskResultMessage(msg)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	d.handleTaskResults(nil, nil, frame)

	// Results file should exist with exact contents.
	tasksDir, err := getTasksDir()
	if err != nil {
		t.Fatalf("getTasksDir: %v", err)
	}
	resultPath := filepath.Join(tasksDir, "results", "task-text-result_result.txt")
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("read result file: %v", err)
	}
	if string(data) != "42" {
		t.Fatalf("result contents = %q, want '42'", string(data))
	}

	// Task status should be SUCCEEDED — receipt of a result message is the
	// success terminal state.
	loaded, _ := LoadSubmittedTaskFile("task-text-result")
	if loaded.Status != tasksubmit.TaskStatusSucceeded {
		t.Fatalf("Status = %q, want SUCCEEDED", loaded.Status)
	}
}

// --- handleTaskResults: file-result path writes <taskID>_<filename> with bytes ---

func TestHandleTaskResultsFileResultSavesUnderTaskIDFilenameKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	seedSubmittedTaskFile(t, "task-file-result")

	msg := &tasksubmit.TaskResultMessage{
		TaskID:      "task-file-result",
		ResultType:  "file",
		Filename:    "answer.bin",
		FileData:    []byte{0x01, 0x02, 0x03, 0x04},
		CompletedAt: "2026-04-20T06:00:00Z",
	}
	frame, err := tasksubmit.MarshalTaskResultMessage(msg)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	d.handleTaskResults(nil, nil, frame)

	tasksDir, _ := getTasksDir()
	filePath := filepath.Join(tasksDir, "results", "task-file-result_answer.bin")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read file-result: %v", err)
	}
	if len(data) != 4 || data[0] != 0x01 || data[3] != 0x04 {
		t.Fatalf("file-result bytes = %v, want [1 2 3 4]", data)
	}

	// Text result path should NOT have been hit (no _result.txt file).
	txtPath := filepath.Join(tasksDir, "results", "task-file-result_result.txt")
	if _, err := os.Stat(txtPath); !os.IsNotExist(err) {
		t.Fatalf("unexpected _result.txt created for ResultType=file; stat err=%v", err)
	}
}

// --- handleTaskResults: empty FileData with ResultType=file falls to text-path ---

func TestHandleTaskResultsFileTypeWithEmptyDataFallsToTextPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	seedSubmittedTaskFile(t, "task-empty-file")

	// ResultType=file but FileData is empty → short-circuit to text branch.
	msg := &tasksubmit.TaskResultMessage{
		TaskID:      "task-empty-file",
		ResultType:  "file",
		Filename:    "should-not-be-used.bin",
		FileData:    nil,
		ResultText:  "fallback-text",
		CompletedAt: "2026-04-20T06:00:00Z",
	}
	frame, _ := tasksubmit.MarshalTaskResultMessage(msg)

	d.handleTaskResults(nil, nil, frame)

	tasksDir, _ := getTasksDir()
	// file-path should NOT exist
	filePath := filepath.Join(tasksDir, "results", "task-empty-file_should-not-be-used.bin")
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("file-path unexpectedly created; stat err=%v", err)
	}
	// text-path should exist with fallback-text
	txtPath := filepath.Join(tasksDir, "results", "task-empty-file_result.txt")
	data, err := os.ReadFile(txtPath)
	if err != nil {
		t.Fatalf("read fallback text: %v", err)
	}
	if string(data) != "fallback-text" {
		t.Fatalf("text = %q, want 'fallback-text'", string(data))
	}
}

// --- handleTaskResults: malformed (wrong type) frame returns cleanly w/o mutation ---

func TestHandleTaskResultsWrongFrameTypeReturnsCleanly(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	d := New(Config{})
	seedSubmittedTaskFile(t, "task-wrong-result-frame")

	// Frame typed as TypeStatusUpdate — Unmarshal should reject it.
	badFrame := &tasksubmit.Frame{Type: tasksubmit.TypeStatusUpdate, Payload: []byte("{}")}

	d.handleTaskResults(nil, nil, badFrame)

	loaded, _ := LoadSubmittedTaskFile("task-wrong-result-frame")
	if loaded.Status != tasksubmit.TaskStatusNew {
		t.Fatalf("Status = %q, want NEW (no mutation on malformed frame)", loaded.Status)
	}

	// No results file should have been written.
	tasksDir, _ := getTasksDir()
	resultsDir := filepath.Join(tasksDir, "results")
	entries, _ := os.ReadDir(resultsDir)
	if len(entries) > 0 {
		t.Fatalf("unexpected entries in results dir: %d", len(entries))
	}
}
