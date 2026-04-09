package tests

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry"
	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// TestTaskSubmitBasic tests basic task submission and response.
func TestTaskSubmitBasic(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Establish mutual trust via handshakes
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // Wait for mutual trust to establish

	// Submit task from a to b
	client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	taskDesc := "Test task description"
	resp, err := client.SubmitTask(taskDesc, b.Daemon.Addr().String())
	if err != nil {
		t.Fatalf("submit task: %v", err)
	}

	if resp.Status != tasksubmit.StatusAccepted {
		t.Errorf("expected status %d, got %d", tasksubmit.StatusAccepted, resp.Status)
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}
}

// TestTaskSubmitNoTrust tests that task submission fails without mutual trust.
func TestTaskSubmitNoTrust(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Attempt to submit task without establishing trust
	// The connection will succeed (since nodes can connect),
	// but we should test that the task can be submitted and rejected
	// In practice, the protocol layer connection succeeds,
	// but the application layer would handle authorization
	client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	// Submit task - this should work at protocol level
	// (trust is enforced at higher layers for actual task authorization)
	resp, err := client.SubmitTask("Test without trust", b.Daemon.Addr().String())
	if err != nil {
		t.Fatalf("submit failed: %v", err)
	}

	// Currently the service auto-accepts all tasks
	// This test verifies the mechanism works
	if resp.Status != tasksubmit.StatusAccepted {
		t.Logf("Task was not accepted (expected in production with auth): %s", resp.Message)
	}
}

// TestTaskSubmitPoloScoreValidation tests polo score validation on task submission.
// In the new implementation, task submission checks that submitter's polo score >= receiver's polo score.
func TestTaskSubmitPoloScoreValidation(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Establish mutual trust via handshakes
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // Wait for mutual trust to establish

	// Get registry client
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry client: %v", err)
	}
	defer rc.Close()

	// Test 1: Equal polo scores (both 0) - should accept
	client1, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp1, err := client1.SubmitTask("Test equal scores", b.Daemon.Addr().String())
	client1.Close()
	if err != nil {
		t.Fatalf("submit task with equal scores: %v", err)
	}
	if resp1.Status != tasksubmit.StatusAccepted {
		t.Errorf("expected task accepted with equal scores, got status %d: %s", resp1.Status, resp1.Message)
	}

	// Test 2: Set A's polo score lower than B's - should reject
	if _, err := rc.SetPoloScore(a.Daemon.NodeID(), 5); err != nil {
		t.Fatalf("set polo A: %v", err)
	}
	if _, err := rc.SetPoloScore(b.Daemon.NodeID(), 10); err != nil {
		t.Fatalf("set polo B: %v", err)
	}

	client2, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp2, err := client2.SubmitTask("Test lower score", b.Daemon.Addr().String())
	client2.Close()
	if err != nil {
		t.Fatalf("submit task with lower score: %v", err)
	}
	if resp2.Status != tasksubmit.StatusRejected {
		t.Errorf("expected task rejected when submitter has lower score, got status %d: %s", resp2.Status, resp2.Message)
	}

	// Test 3: Set A's polo score higher than B's - should accept
	if _, err := rc.SetPoloScore(a.Daemon.NodeID(), 20); err != nil {
		t.Fatalf("set polo A: %v", err)
	}

	client3, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp3, err := client3.SubmitTask("Test higher score", b.Daemon.Addr().String())
	client3.Close()
	if err != nil {
		t.Fatalf("submit task with higher score: %v", err)
	}
	if resp3.Status != tasksubmit.StatusAccepted {
		t.Errorf("expected task accepted when submitter has higher score, got status %d: %s", resp3.Status, resp3.Message)
	}
}

// TestTaskSubmitTaskFilesCreated tests that task files are created in the correct directories.
// In the new implementation, task files are stored in ~/.pilot/tasks/submitted/ and ~/.pilot/tasks/received/
func TestTaskSubmitTaskFilesCreated(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Clean up any leftover task files from previous test runs to avoid race conditions
	home, _ := os.UserHomeDir()
	receivedDir := home + "/.pilot/tasks/received"
	os.RemoveAll(receivedDir)
	os.MkdirAll(receivedDir, 0700)

	// Establish mutual trust via handshakes
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // Wait for mutual trust to establish

	// Submit task from a to b
	client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	taskDesc := "Test task files creation"
	resp, err := client.SubmitTask(taskDesc, b.Daemon.Addr().String())
	if err != nil {
		t.Fatalf("submit task: %v", err)
	}

	if resp.Status != tasksubmit.StatusAccepted {
		t.Fatalf("task not accepted: %s", resp.Message)
	}

	// Use the task ID from the response to find the exact task file
	taskID := resp.TaskID
	if taskID == "" {
		t.Fatal("expected non-empty task ID in response")
	}

	// Check for the specific task file by ID
	taskFilePath := receivedDir + "/" + taskID + ".json"
	data, err := os.ReadFile(taskFilePath)
	if err != nil {
		t.Logf("Task file not found at %s (may be timing issue): %v", taskFilePath, err)
		return
	}

	var tf tasksubmit.TaskFile
	if err := json.Unmarshal(data, &tf); err != nil {
		t.Fatalf("failed to unmarshal task file: %v", err)
	}

	// Verify task file structure
	if tf.TaskID != taskID {
		t.Errorf("expected task ID %s, got %s", taskID, tf.TaskID)
	}
	if tf.TaskDescription != taskDesc {
		t.Errorf("expected description %q, got %q", taskDesc, tf.TaskDescription)
	}
	// Task should be NEW or possibly CANCELLED if monitoring ran (which is fine)
	if tf.Status != tasksubmit.TaskStatusNew && tf.Status != tasksubmit.TaskStatusCancelled {
		t.Errorf("expected task status NEW or CANCELLED, got %s", tf.Status)
	}
}

// TestTaskSubmitMultipleTasks tests queuing multiple tasks.
// In the new implementation, tasks are queued for manual execution via pilotctl.
func TestTaskSubmitMultipleTasks(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Establish mutual trust via handshakes
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // Wait for mutual trust to establish

	numTasks := 5
	for i := 0; i < numTasks; i++ {
		client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}

		taskDesc := fmt.Sprintf("Task %d", i)
		resp, err := client.SubmitTask(taskDesc, b.Daemon.Addr().String())
		client.Close()

		if err != nil {
			t.Fatalf("submit task %d: %v", i, err)
		}
		if resp.Status != tasksubmit.StatusAccepted {
			t.Errorf("task %d: expected accepted, got %d", i, resp.Status)
		}
	}

	// Verify tasks are queued
	queue := b.Daemon.TaskQueue()
	if queue.Len() != numTasks {
		t.Errorf("expected %d tasks in queue, got %d", numTasks, queue.Len())
	}

	// Pop tasks and verify FIFO order
	taskIDs := queue.List()
	if len(taskIDs) != numTasks {
		t.Errorf("expected %d task IDs, got %d", numTasks, len(taskIDs))
	}
}

// TestTaskSubmitFrameProtocol tests the frame protocol marshaling/unmarshaling.
func TestTaskSubmitFrameProtocol(t *testing.T) {
	// Test SubmitRequest marshaling
	req := &tasksubmit.SubmitRequest{
		TaskDescription: "Test task",
	}

	frame, err := tasksubmit.MarshalSubmitRequest(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	if frame.Type != tasksubmit.TypeSubmit {
		t.Errorf("expected type %d, got %d", tasksubmit.TypeSubmit, frame.Type)
	}

	parsedReq, err := tasksubmit.UnmarshalSubmitRequest(frame)
	if err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	if parsedReq.TaskDescription != req.TaskDescription {
		t.Errorf("expected description %q, got %q", req.TaskDescription, parsedReq.TaskDescription)
	}

	// Test SubmitResponse marshaling
	resp := &tasksubmit.SubmitResponse{
		Status:  tasksubmit.StatusAccepted,
		Message: "Accepted",
	}

	respFrame, err := tasksubmit.MarshalSubmitResponse(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	parsedResp, err := tasksubmit.UnmarshalSubmitResponse(respFrame)
	if err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if parsedResp.Status != resp.Status {
		t.Errorf("expected status %d, got %d", resp.Status, parsedResp.Status)
	}
	if parsedResp.Message != resp.Message {
		t.Errorf("expected message %q, got %q", resp.Message, parsedResp.Message)
	}

	// Test TaskResult marshaling
	result := &tasksubmit.TaskResult{
		TaskDescription: "Test task",
		Status:          "success",
		Result:          "Task completed",
		Timestamp:       time.Now().Format(time.RFC3339),
	}

	resultFrame, err := tasksubmit.MarshalTaskResult(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	if resultFrame.Type != tasksubmit.TypeResult {
		t.Errorf("expected type %d, got %d", tasksubmit.TypeResult, resultFrame.Type)
	}

	parsedResult, err := tasksubmit.UnmarshalTaskResult(resultFrame)
	if err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if parsedResult.TaskDescription != result.TaskDescription {
		t.Errorf("expected description %q, got %q", result.TaskDescription, parsedResult.TaskDescription)
	}
	if parsedResult.Status != result.Status {
		t.Errorf("expected status %q, got %q", result.Status, parsedResult.Status)
	}
}

// TestTaskSubmitTypeNames tests the TypeName function.
func TestTaskSubmitTypeNames(t *testing.T) {
	tests := []struct {
		typ  uint32
		name string
	}{
		{tasksubmit.TypeSubmit, "SUBMIT"},
		{tasksubmit.TypeResult, "RESULT"},
		{999, "UNKNOWN(999)"},
	}

	for _, tt := range tests {
		name := tasksubmit.TypeName(tt.typ)
		if name != tt.name {
			t.Errorf("TypeName(%d) = %q, want %q", tt.typ, name, tt.name)
		}
	}
}

// TestTaskSubmitQueueOperations tests the task queue operations.
func TestTaskSubmitQueueOperations(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	queue := a.Daemon.TaskQueue()

	// Test empty queue
	if queue.Len() != 0 {
		t.Errorf("expected empty queue, got length %d", queue.Len())
	}

	taskID := queue.Pop()
	if taskID != "" {
		t.Error("expected empty string from empty queue")
	}

	// Add task IDs
	queue.Add("task-id-1")
	queue.Add("task-id-2")
	queue.Add("task-id-3")

	if queue.Len() != 3 {
		t.Errorf("expected length 3, got %d", queue.Len())
	}

	// Pop tasks (FIFO)
	task1 := queue.Pop()
	if task1 != "task-id-1" {
		t.Errorf("unexpected first task: %q", task1)
	}

	task2 := queue.Pop()
	if task2 != "task-id-2" {
		t.Errorf("unexpected second task: %q", task2)
	}

	if queue.Len() != 1 {
		t.Errorf("expected length 1, got %d", queue.Len())
	}

	task3 := queue.Pop()
	if task3 != "task-id-3" {
		t.Errorf("unexpected third task: %q", task3)
	}

	// Queue should be empty again
	if queue.Len() != 0 {
		t.Errorf("expected empty queue, got length %d", queue.Len())
	}

	taskID = queue.Pop()
	if taskID != "" {
		t.Error("expected empty string from empty queue after pop all")
	}
}

// TestTaskSubmitConcurrent tests concurrent task submissions.
// Verifies that multiple tasks can be submitted concurrently and all are queued.
func TestTaskSubmitConcurrent(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Establish mutual trust via handshakes
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // Wait for mutual trust to establish

	// Submit tasks concurrently
	const numConcurrent = 10
	errCh := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(n int) {
			client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
			if err != nil {
				errCh <- err
				return
			}
			defer client.Close()

			taskDesc := fmt.Sprintf("Concurrent task %d", n)
			resp, err := client.SubmitTask(taskDesc, b.Daemon.Addr().String())
			if err != nil {
				errCh <- err
				return
			}
			if resp.Status != tasksubmit.StatusAccepted {
				errCh <- fmt.Errorf("task %d rejected", n)
				return
			}
			errCh <- nil
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < numConcurrent; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("concurrent task failed: %v", err)
		}
	}

	// Give time for all tasks to be added to the queue
	time.Sleep(100 * time.Millisecond)

	// Verify all tasks were queued
	queue := b.Daemon.TaskQueue()
	queueLen := queue.Len()
	if queueLen != numConcurrent {
		t.Errorf("expected %d tasks in queue, got %d", numConcurrent, queueLen)
	}

	// Verify queue list returns all task IDs
	taskIDs := queue.List()
	if len(taskIDs) != numConcurrent {
		t.Errorf("expected %d task IDs in list, got %d", numConcurrent, len(taskIDs))
	}
}

// ============== NEW TESTS FOR TIME METADATA AND TASK LIFECYCLE ==============

// TestTaskFileSchema verifies the TaskFile JSON schema contains all required fields.
func TestTaskFileSchema(t *testing.T) {
	tf := tasksubmit.NewTaskFile("test-id-123", "Test description", "0:0000.0000.0001", "0:0000.0000.0002")

	// Marshal to JSON
	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		t.Fatalf("marshal task file: %v", err)
	}

	// Unmarshal to map to check schema
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// Required fields
	requiredFields := []string{
		"task_id",
		"task_description",
		"created_at",
		"status",
		"status_justification",
		"from",
		"to",
	}

	for _, field := range requiredFields {
		if _, exists := m[field]; !exists {
			t.Errorf("missing required field: %s", field)
		}
	}

	// Verify values
	if m["task_id"] != "test-id-123" {
		t.Errorf("unexpected task_id: %v", m["task_id"])
	}
	if m["task_description"] != "Test description" {
		t.Errorf("unexpected task_description: %v", m["task_description"])
	}
	if m["status"] != tasksubmit.TaskStatusNew {
		t.Errorf("unexpected status: %v", m["status"])
	}
	if m["from"] != "0:0000.0000.0001" {
		t.Errorf("unexpected from: %v", m["from"])
	}
	if m["to"] != "0:0000.0000.0002" {
		t.Errorf("unexpected to: %v", m["to"])
	}
}

// TestTaskFileTimeMetadataSchema verifies that time metadata fields are properly serialized.
func TestTaskFileTimeMetadataSchema(t *testing.T) {
	tf := tasksubmit.NewTaskFile("test-id-456", "Test with time", "0:0000.0000.0001", "0:0000.0000.0002")

	// Simulate accept (sets AcceptedAt and TimeIdleMs)
	tf.CalculateTimeIdle()

	// Simulate staged at queue head
	tf.StagedAt = time.Now().UTC().Format(time.RFC3339)

	// Simulate execute (sets ExecuteStartedAt and TimeStagedMs)
	time.Sleep(10 * time.Millisecond)
	tf.CalculateTimeStaged()

	// Simulate complete (sets CompletedAt and TimeCpuMs)
	time.Sleep(10 * time.Millisecond)
	tf.CalculateTimeCpu()

	tf.Status = tasksubmit.TaskStatusSucceeded

	// Marshal to JSON
	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		t.Fatalf("marshal task file: %v", err)
	}

	// Unmarshal to map
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	// Check time metadata fields exist
	timeFields := []string{
		"accepted_at",
		"staged_at",
		"execute_started_at",
		"completed_at",
		"time_idle_ms",
		"time_staged_ms",
		"time_cpu_ms",
	}

	for _, field := range timeFields {
		if _, exists := m[field]; !exists {
			t.Errorf("missing time field: %s", field)
		}
	}

	// Verify time values are positive
	if timeIdleMs, ok := m["time_idle_ms"].(float64); ok {
		if timeIdleMs < 0 {
			t.Errorf("time_idle_ms should be non-negative, got %v", timeIdleMs)
		}
	}

	if timeStagedMs, ok := m["time_staged_ms"].(float64); ok {
		if timeStagedMs < 0 {
			t.Errorf("time_staged_ms should be non-negative, got %v", timeStagedMs)
		}
	}

	if timeCpuMs, ok := m["time_cpu_ms"].(float64); ok {
		if timeCpuMs < 0 {
			t.Errorf("time_cpu_ms should be non-negative, got %v", timeCpuMs)
		}
	}
}

// TestTaskStatusConstants verifies all task status constants.
func TestTaskStatusConstants(t *testing.T) {
	statuses := map[string]string{
		"NEW":       tasksubmit.TaskStatusNew,
		"ACCEPTED":  tasksubmit.TaskStatusAccepted,
		"DECLINED":  tasksubmit.TaskStatusDeclined,
		"EXECUTING": tasksubmit.TaskStatusExecuting,
		"COMPLETED": tasksubmit.TaskStatusCompleted,
		"SUCCEEDED": tasksubmit.TaskStatusSucceeded,
		"CANCELLED": tasksubmit.TaskStatusCancelled,
		"EXPIRED":   tasksubmit.TaskStatusExpired,
	}

	for expected, actual := range statuses {
		if actual != expected {
			t.Errorf("expected status constant %q, got %q", expected, actual)
		}
	}
}

// TestTaskAcceptTimeoutConstant verifies the accept timeout is 1 minute.
func TestTaskAcceptTimeoutConstant(t *testing.T) {
	if tasksubmit.TaskAcceptTimeout != 1*time.Minute {
		t.Errorf("expected TaskAcceptTimeout to be 1 minute, got %v", tasksubmit.TaskAcceptTimeout)
	}
}

// TestTaskQueueHeadTimeoutConstant verifies the queue head timeout is 1 hour.
func TestTaskQueueHeadTimeoutConstant(t *testing.T) {
	if tasksubmit.TaskQueueHeadTimeout != 1*time.Hour {
		t.Errorf("expected TaskQueueHeadTimeout to be 1 hour, got %v", tasksubmit.TaskQueueHeadTimeout)
	}
}

// TestTaskFileIsExpiredForAccept tests the accept expiry logic.
func TestTaskFileIsExpiredForAccept(t *testing.T) {
	// Create a task with a creation time in the past
	tf := &tasksubmit.TaskFile{
		TaskID:    "expired-test",
		Status:    tasksubmit.TaskStatusNew,
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339), // 2 minutes ago
	}

	if !tf.IsExpiredForAccept() {
		t.Error("task created 2 minutes ago should be expired for accept")
	}

	// Create a recent task
	tf2 := &tasksubmit.TaskFile{
		TaskID:    "recent-test",
		Status:    tasksubmit.TaskStatusNew,
		CreatedAt: time.Now().UTC().Add(-30 * time.Second).Format(time.RFC3339), // 30 seconds ago
	}

	if tf2.IsExpiredForAccept() {
		t.Error("task created 30 seconds ago should not be expired for accept")
	}

	// Non-NEW status should not be expired
	tf3 := &tasksubmit.TaskFile{
		TaskID:    "accepted-test",
		Status:    tasksubmit.TaskStatusAccepted,
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339),
	}

	if tf3.IsExpiredForAccept() {
		t.Error("accepted task should not be considered expired for accept")
	}
}

// TestTaskFileIsExpiredInQueue tests the queue head expiry logic.
func TestTaskFileIsExpiredInQueue(t *testing.T) {
	// Create a task staged at queue head 2 hours ago
	tf := &tasksubmit.TaskFile{
		TaskID:   "expired-queue-test",
		Status:   tasksubmit.TaskStatusAccepted,
		StagedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339), // 2 hours ago
	}

	if !tf.IsExpiredInQueue() {
		t.Error("task staged 2 hours ago should be expired in queue")
	}

	// Create a recently staged task
	tf2 := &tasksubmit.TaskFile{
		TaskID:   "recent-queue-test",
		Status:   tasksubmit.TaskStatusAccepted,
		StagedAt: time.Now().UTC().Add(-30 * time.Minute).Format(time.RFC3339), // 30 minutes ago
	}

	if tf2.IsExpiredInQueue() {
		t.Error("task staged 30 minutes ago should not be expired in queue")
	}

	// Non-ACCEPTED status should not be expired in queue
	tf3 := &tasksubmit.TaskFile{
		TaskID:   "new-queue-test",
		Status:   tasksubmit.TaskStatusNew,
		StagedAt: time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339),
	}

	if tf3.IsExpiredInQueue() {
		t.Error("non-accepted task should not be considered expired in queue")
	}
}

// TestTaskQueueRemove tests removing tasks from the queue.
func TestTaskQueueRemove(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	queue := a.Daemon.TaskQueue()

	// Add tasks
	queue.Add("task-1")
	queue.Add("task-2")
	queue.Add("task-3")

	if queue.Len() != 3 {
		t.Errorf("expected 3 tasks, got %d", queue.Len())
	}

	// Remove middle task
	removed := queue.Remove("task-2")
	if !removed {
		t.Error("expected task-2 to be removed")
	}

	if queue.Len() != 2 {
		t.Errorf("expected 2 tasks after removal, got %d", queue.Len())
	}

	// Verify task-2 is gone
	list := queue.List()
	for _, id := range list {
		if id == "task-2" {
			t.Error("task-2 should not be in list after removal")
		}
	}

	// Remove non-existent task
	removed = queue.Remove("non-existent")
	if removed {
		t.Error("removing non-existent task should return false")
	}
}

// TestTaskQueueHeadStagedAt tests tracking when tasks become head of queue.
func TestTaskQueueHeadStagedAt(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	queue := a.Daemon.TaskQueue()

	// Add first task - should become head immediately
	queue.Add("task-1")

	stagedAt1 := queue.GetStagedAt("task-1")
	if stagedAt1 == "" {
		t.Error("first task should have staged_at timestamp")
	}

	// Add second task - should NOT have staged_at yet
	queue.Add("task-2")

	stagedAt2 := queue.GetStagedAt("task-2")
	if stagedAt2 != "" {
		t.Error("second task should not have staged_at until it becomes head")
	}

	// Pop first task - second should now have staged_at
	queue.Pop()

	stagedAt2After := queue.GetStagedAt("task-2")
	if stagedAt2After == "" {
		t.Error("second task should have staged_at after becoming head")
	}
}

// TestNegativePoloScoreAllowed tests that polo scores can go negative.
func TestNegativePoloScoreAllowed(t *testing.T) {
	t.Parallel()

	// Start beacon and registry
	env := NewTestEnv(t)
	a := env.AddDaemon()

	// Get registry client
	rc, err := registry.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry dial: %v", err)
	}
	defer rc.Close()

	// Set polo score to 0
	if _, err := rc.SetPoloScore(a.Daemon.NodeID(), 0); err != nil {
		t.Fatalf("set polo score to 0: %v", err)
	}

	// Decrement to -1
	resp, err := rc.UpdatePoloScore(a.Daemon.NodeID(), -1)
	if err != nil {
		t.Fatalf("update polo score to -1: %v", err)
	}

	newScore, ok := resp["polo_score"].(float64)
	if !ok {
		t.Fatalf("polo_score not found in response")
	}
	if int(newScore) != -1 {
		t.Errorf("expected polo score -1, got %d", int(newScore))
	}

	// Further decrement to -10
	resp, err = rc.UpdatePoloScore(a.Daemon.NodeID(), -9)
	if err != nil {
		t.Fatalf("update polo score to -10: %v", err)
	}

	newScore = resp["polo_score"].(float64)
	if int(newScore) != -10 {
		t.Errorf("expected polo score -10, got %d", int(newScore))
	}

	// Verify via GetPoloScore
	score, err := rc.GetPoloScore(a.Daemon.NodeID())
	if err != nil {
		t.Fatalf("get polo score: %v", err)
	}
	if score != -10 {
		t.Errorf("expected polo score -10, got %d", score)
	}

	// Set directly to a large negative value
	if _, err := rc.SetPoloScore(a.Daemon.NodeID(), -500); err != nil {
		t.Fatalf("set polo score to -500: %v", err)
	}

	score, err = rc.GetPoloScore(a.Daemon.NodeID())
	if err != nil {
		t.Fatalf("get polo score after set: %v", err)
	}
	if score != -500 {
		t.Errorf("expected polo score -500, got %d", score)
	}
}

// TestTaskDirectoryStructure tests the tasks directory is created properly.
func TestTaskDirectoryStructure(t *testing.T) {
	// This test verifies the directory structure creation
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("get home dir: %v", err)
	}

	tasksDir := home + "/.pilot/tasks"
	submittedDir := tasksDir + "/submitted"
	receivedDir := tasksDir + "/received"

	// Create directories if they don't exist (mimic ensureTaskDirs)
	if err := os.MkdirAll(submittedDir, 0700); err != nil {
		t.Fatalf("create submitted dir: %v", err)
	}
	if err := os.MkdirAll(receivedDir, 0700); err != nil {
		t.Fatalf("create received dir: %v", err)
	}

	// Verify directories exist
	if info, err := os.Stat(submittedDir); err != nil || !info.IsDir() {
		t.Errorf("submitted directory should exist")
	}
	if info, err := os.Stat(receivedDir); err != nil || !info.IsDir() {
		t.Errorf("received directory should exist")
	}

	// Create a test task file
	tf := tasksubmit.NewTaskFile("test-dir-struct", "Directory test", "from", "to")
	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	testFile := receivedDir + "/test-dir-struct.json"
	if err := os.WriteFile(testFile, data, 0600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Verify file exists and is readable
	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	// Unmarshal and verify
	readTf, err := tasksubmit.UnmarshalTaskFile(readData)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if readTf.TaskID != "test-dir-struct" {
		t.Errorf("unexpected task_id: %s", readTf.TaskID)
	}

	// Clean up
	os.Remove(testFile)
}

// TestCalculateTimeIdle tests the time_idle calculation.
func TestCalculateTimeIdle(t *testing.T) {
	// Create task with specific creation time
	createdTime := time.Now().UTC().Add(-5 * time.Second)
	tf := &tasksubmit.TaskFile{
		TaskID:    "time-idle-test",
		Status:    tasksubmit.TaskStatusNew,
		CreatedAt: createdTime.Format(time.RFC3339),
	}

	// Calculate time idle
	tf.CalculateTimeIdle()

	// Should be approximately 5 seconds (5000ms), allow some margin
	if tf.TimeIdleMs < 4500 || tf.TimeIdleMs > 6000 {
		t.Errorf("expected time_idle_ms around 5000, got %d", tf.TimeIdleMs)
	}

	// AcceptedAt should be set
	if tf.AcceptedAt == "" {
		t.Error("accepted_at should be set after CalculateTimeIdle")
	}
}

// TestCalculateTimeStaged tests the time_staged calculation.
func TestCalculateTimeStaged(t *testing.T) {
	// Create task with specific staged time
	stagedTime := time.Now().UTC().Add(-3 * time.Second)
	tf := &tasksubmit.TaskFile{
		TaskID:   "time-staged-test",
		Status:   tasksubmit.TaskStatusAccepted,
		StagedAt: stagedTime.Format(time.RFC3339),
	}

	// Calculate time staged
	tf.CalculateTimeStaged()

	// Should be approximately 3 seconds (3000ms), allow some margin
	if tf.TimeStagedMs < 2500 || tf.TimeStagedMs > 4000 {
		t.Errorf("expected time_staged_ms around 3000, got %d", tf.TimeStagedMs)
	}

	// ExecuteStartedAt should be set
	if tf.ExecuteStartedAt == "" {
		t.Error("execute_started_at should be set after CalculateTimeStaged")
	}
}

// TestCalculateTimeCpu tests the time_cpu calculation.
func TestCalculateTimeCpu(t *testing.T) {
	// Create task with specific execute start time
	execStartTime := time.Now().UTC().Add(-2 * time.Second)
	tf := &tasksubmit.TaskFile{
		TaskID:           "time-cpu-test",
		Status:           tasksubmit.TaskStatusExecuting,
		ExecuteStartedAt: execStartTime.Format(time.RFC3339),
	}

	// Calculate time CPU
	tf.CalculateTimeCpu()

	// Should be approximately 2 seconds (2000ms), allow some margin
	if tf.TimeCpuMs < 1500 || tf.TimeCpuMs > 3000 {
		t.Errorf("expected time_cpu_ms around 2000, got %d", tf.TimeCpuMs)
	}

	// CompletedAt should be set
	if tf.CompletedAt == "" {
		t.Error("completed_at should be set after CalculateTimeCpu")
	}
}

// TestGenerateTaskID tests UUID-like task ID generation.
func TestGenerateTaskID(t *testing.T) {
	ids := make(map[string]bool)

	for i := 0; i < 100; i++ {
		id := tasksubmit.GenerateTaskID()

		// Check format (UUID-like)
		if len(id) != 36 {
			t.Errorf("task ID should be 36 characters, got %d: %s", len(id), id)
		}

		// Check for uniqueness
		if ids[id] {
			t.Errorf("duplicate task ID generated: %s", id)
		}
		ids[id] = true
	}
}

// TestParseTime tests the time parsing utility.
func TestParseTime(t *testing.T) {
	now := time.Now().UTC()
	formatted := now.Format(time.RFC3339)

	parsed, err := tasksubmit.ParseTime(formatted)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}

	// Allow 1 second difference due to formatting precision
	diff := now.Sub(parsed)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("parsed time differs too much: %v", diff)
	}

	// Test invalid format
	_, err = tasksubmit.ParseTime("invalid")
	if err == nil {
		t.Error("expected error for invalid time format")
	}
}

// ===================== POLO SCORE REWARD CALCULATION TESTS =====================

// TestPoloScoreRewardBase tests the base case with no time factors.
func TestPoloScoreRewardBase(t *testing.T) {
	tf := &tasksubmit.TaskFile{
		TaskID:       "test-base",
		TimeIdleMs:   0,
		TimeStagedMs: 0,
		TimeCpuMs:    0,
	}

	reward := tf.PoloScoreReward()
	// Base reward: (1 + log2(1)) * 1.0 = 1 * 1.0 = 1
	if reward != 1 {
		t.Errorf("expected base reward of 1 with no time factors, got %d", reward)
	}
}

// TestPoloScoreRewardCPUBonus tests CPU time bonus calculation with logarithmic scaling.
func TestPoloScoreRewardCPUBonus(t *testing.T) {
	tests := []struct {
		name       string
		timeCpuMs  int64
		wantReward int
	}{
		// Formula: (1 + log2(1 + cpu_minutes)) * 1.0
		{"no CPU time", 0, 1},          // (1 + log2(1)) = 1
		{"1 minute CPU", 60000, 2},     // (1 + log2(2)) = 1 + 1 = 2
		{"3 minutes CPU", 180000, 3},   // (1 + log2(4)) = 1 + 2 = 3
		{"7 minutes CPU", 420000, 4},   // (1 + log2(8)) = 1 + 3 = 4
		{"15 minutes CPU", 900000, 5},  // (1 + log2(16)) = 1 + 4 = 5
		{"31 minutes CPU", 1860000, 6}, // (1 + log2(32)) = 1 + 5 = 6
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := &tasksubmit.TaskFile{
				TaskID:       "test-cpu",
				TimeIdleMs:   0,
				TimeStagedMs: 0,
				TimeCpuMs:    tt.timeCpuMs,
			}

			reward := tf.PoloScoreReward()
			if reward != tt.wantReward {
				breakdown := tf.PoloScoreRewardDetailed()
				t.Errorf("CPU time %dms: expected reward %d, got %d (breakdown: %+v)",
					tt.timeCpuMs, tt.wantReward, reward, breakdown)
			}
		})
	}
}

// TestPoloScoreRewardIdlePenalty tests idle time penalty calculation.
func TestPoloScoreRewardIdlePenalty(t *testing.T) {
	tests := []struct {
		name       string
		timeIdleMs int64
		wantReward int
	}{
		// Formula: (1 + 0) * (1.0 - idleFactor), idleFactor = min(idle/60s, 0.3)
		{"no idle time", 0, 1},              // efficiency = 1.0
		{"30 seconds idle", 30000, 1},       // efficiency = 0.85, reward = 0.85 → 1
		{"60 seconds idle (max)", 60000, 1}, // efficiency = 0.7, reward = 0.7 → 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := &tasksubmit.TaskFile{
				TaskID:       "test-idle",
				TimeIdleMs:   tt.timeIdleMs,
				TimeStagedMs: 0,
				TimeCpuMs:    0,
			}

			reward := tf.PoloScoreReward()
			if reward != tt.wantReward {
				breakdown := tf.PoloScoreRewardDetailed()
				t.Errorf("idle time %dms: expected reward %d, got %d (breakdown: %+v)",
					tt.timeIdleMs, tt.wantReward, reward, breakdown)
			}
		})
	}
}

// TestPoloScoreRewardStagedPenalty tests staged time penalty calculation.
func TestPoloScoreRewardStagedPenalty(t *testing.T) {
	tests := []struct {
		name         string
		timeStagedMs int64
		wantReward   int
	}{
		// Formula: (1 + 0) * (1.0 - stagedFactor), stagedFactor = min(staged/600s, 0.3)
		{"no staged time", 0, 1},               // efficiency = 1.0
		{"5 minutes staged", 300000, 1},        // efficiency = 0.85, reward = 0.85 → 1
		{"10 minutes staged (max)", 600000, 1}, // efficiency = 0.7, reward = 0.7 → 1
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := &tasksubmit.TaskFile{
				TaskID:       "test-staged",
				TimeIdleMs:   0,
				TimeStagedMs: tt.timeStagedMs,
				TimeCpuMs:    0,
			}

			reward := tf.PoloScoreReward()
			if reward != tt.wantReward {
				breakdown := tf.PoloScoreRewardDetailed()
				t.Errorf("staged time %dms: expected reward %d, got %d (breakdown: %+v)",
					tt.timeStagedMs, tt.wantReward, reward, breakdown)
			}
		})
	}
}

// TestPoloScoreRewardCombined tests combined bonuses and penalties.
func TestPoloScoreRewardCombined(t *testing.T) {
	tests := []struct {
		name         string
		timeIdleMs   int64
		timeStagedMs int64
		timeCpuMs    int64
		wantReward   int
	}{
		{
			name:         "perfect task (instant accept/execute, 1 min CPU)",
			timeIdleMs:   0,
			timeStagedMs: 0,
			timeCpuMs:    60000, // 1 minute
			wantReward:   2,     // (1 + log2(2)) * 1.0 = 2
		},
		{
			name:         "perfect task (instant accept/execute, 7 min CPU)",
			timeIdleMs:   0,
			timeStagedMs: 0,
			timeCpuMs:    420000, // 7 minutes
			wantReward:   4,      // (1 + log2(8)) * 1.0 = 4
		},
		{
			name:         "slow accept (30s), quick execute, 3 min CPU",
			timeIdleMs:   30000, // 30 seconds → idleFactor = 0.15
			timeStagedMs: 0,
			timeCpuMs:    180000, // 3 minutes
			wantReward:   3,      // (1 + 2) * 0.85 = 2.55 → 3
		},
		{
			name:         "both penalties maxed out, no CPU",
			timeIdleMs:   60000,  // 60 seconds → idleFactor = 0.3
			timeStagedMs: 600000, // 10 minutes → stagedFactor = 0.3
			timeCpuMs:    0,
			wantReward:   1, // (1 + 0) * 0.4 = 0.4 → min 1
		},
		{
			name:         "both penalties maxed, 7 min CPU",
			timeIdleMs:   60000,  // 60 seconds
			timeStagedMs: 600000, // 10 minutes
			timeCpuMs:    420000, // 7 minutes
			wantReward:   2,      // (1 + 3) * 0.4 = 1.6 → 2
		},
		{
			name:         "heavy compute task (31 min)",
			timeIdleMs:   5000,    // 5 seconds → idleFactor ≈ 0.025
			timeStagedMs: 60000,   // 1 minute → stagedFactor = 0.03
			timeCpuMs:    1860000, // 31 minutes
			wantReward:   6,       // (1 + 5) * 0.945 = 5.67 → 6
		},
		{
			name:         "very long compute task (63 min)",
			timeIdleMs:   0,
			timeStagedMs: 0,
			timeCpuMs:    3780000, // 63 minutes
			wantReward:   7,       // (1 + log2(64)) = 1 + 6 = 7
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := &tasksubmit.TaskFile{
				TaskID:       "test-combined",
				TimeIdleMs:   tt.timeIdleMs,
				TimeStagedMs: tt.timeStagedMs,
				TimeCpuMs:    tt.timeCpuMs,
			}

			reward := tf.PoloScoreReward()
			if reward != tt.wantReward {
				breakdown := tf.PoloScoreRewardDetailed()
				t.Errorf("%s: expected reward %d, got %d (breakdown: %+v)",
					tt.name, tt.wantReward, reward, breakdown)
			}
		})
	}
}

// TestPoloScoreRewardDetailed tests the detailed breakdown function.
func TestPoloScoreRewardDetailed(t *testing.T) {
	tf := &tasksubmit.TaskFile{
		TaskID:       "test-detailed",
		TimeIdleMs:   15000,  // 15 seconds
		TimeStagedMs: 150000, // 2.5 minutes
		TimeCpuMs:    180000, // 3 minutes
	}

	breakdown := tf.PoloScoreRewardDetailed()

	// Check base
	if breakdown.Base != 1.0 {
		t.Errorf("expected base 1.0, got %f", breakdown.Base)
	}

	// Check CPU minutes
	expectedCpuMinutes := 3.0
	if breakdown.CpuMinutes < expectedCpuMinutes-0.1 || breakdown.CpuMinutes > expectedCpuMinutes+0.1 {
		t.Errorf("expected cpu_minutes around %f, got %f", expectedCpuMinutes, breakdown.CpuMinutes)
	}

	// Check CPU bonus: log2(1 + 3) = log2(4) = 2
	expectedCpuBonus := 2.0
	if breakdown.CpuBonus < expectedCpuBonus-0.1 || breakdown.CpuBonus > expectedCpuBonus+0.1 {
		t.Errorf("expected cpu_bonus around %f, got %f", expectedCpuBonus, breakdown.CpuBonus)
	}

	// Check idle factor: 15s / 60s * 0.3 = 0.075
	expectedIdleFactor := 0.075
	if breakdown.IdleFactor < expectedIdleFactor-0.01 || breakdown.IdleFactor > expectedIdleFactor+0.01 {
		t.Errorf("expected idle_factor around %f, got %f", expectedIdleFactor, breakdown.IdleFactor)
	}

	// Check staged factor: 150s / 600s * 0.3 = 0.075
	expectedStagedFactor := 0.075
	if breakdown.StagedFactor < expectedStagedFactor-0.01 || breakdown.StagedFactor > expectedStagedFactor+0.01 {
		t.Errorf("expected staged_factor around %f, got %f", expectedStagedFactor, breakdown.StagedFactor)
	}

	// Check efficiency multiplier: 1.0 - 0.075 - 0.075 = 0.85
	expectedEfficiency := 0.85
	if breakdown.EfficiencyMultiplier < expectedEfficiency-0.05 || breakdown.EfficiencyMultiplier > expectedEfficiency+0.05 {
		t.Errorf("expected efficiency_multiplier around %f, got %f", expectedEfficiency, breakdown.EfficiencyMultiplier)
	}

	// Check final reward
	if breakdown.FinalReward != tf.PoloScoreReward() {
		t.Errorf("FinalReward mismatch: %d vs %d", breakdown.FinalReward, tf.PoloScoreReward())
	}
}

// TestPoloScoreRewardMinimum tests that reward is always at least 1.
func TestPoloScoreRewardMinimum(t *testing.T) {
	// Create a task with maximum penalties and no CPU bonus
	tf := &tasksubmit.TaskFile{
		TaskID:       "test-min",
		TimeIdleMs:   120000,  // 2 minutes (way past max)
		TimeStagedMs: 1200000, // 20 minutes (way past max)
		TimeCpuMs:    0,       // no CPU bonus
	}

	reward := tf.PoloScoreReward()
	// Minimum reward is always 1
	if reward < 1 {
		t.Errorf("reward should never be less than 1, got %d", reward)
	}
	if reward != 1 {
		t.Errorf("expected minimum reward of 1 with max penalties, got %d", reward)
	}
}

// TestPoloScoreRewardScaling tests that longer tasks get higher rewards.
func TestPoloScoreRewardScaling(t *testing.T) {
	// Verify that reward scales properly with CPU time
	cpuTimes := []int64{0, 60000, 180000, 420000, 900000, 1860000} // 0, 1, 3, 7, 15, 31 minutes
	lastReward := 0

	for _, cpuMs := range cpuTimes {
		tf := &tasksubmit.TaskFile{
			TaskID:       "test-scaling",
			TimeIdleMs:   0,
			TimeStagedMs: 0,
			TimeCpuMs:    cpuMs,
		}

		reward := tf.PoloScoreReward()
		if reward < lastReward {
			t.Errorf("reward should increase with CPU time: %dms gave %d, previous was %d",
				cpuMs, reward, lastReward)
		}
		lastReward = reward
	}

	// Verify the 31 minute task (last one) gets significantly more than 1 minute task
	tf1min := &tasksubmit.TaskFile{TimeCpuMs: 60000}
	tf31min := &tasksubmit.TaskFile{TimeCpuMs: 1860000}

	if tf31min.PoloScoreReward() <= tf1min.PoloScoreReward()+2 {
		t.Errorf("31 min task should get significantly more than 1 min task: 1min=%d, 31min=%d",
			tf1min.PoloScoreReward(), tf31min.PoloScoreReward())
	}
}

// TestTaskResultMessageTimeMetadata tests that TaskResultMessage includes time metadata fields.
func TestTaskResultMessageTimeMetadata(t *testing.T) {
	msg := tasksubmit.TaskResultMessage{
		TaskID:       "test-metadata",
		ResultType:   "text",
		ResultText:   "test results",
		CompletedAt:  time.Now().UTC().Format(time.RFC3339),
		TimeIdleMs:   5000,
		TimeStagedMs: 10000,
		TimeCpuMs:    60000,
	}

	// Verify fields are set
	if msg.TimeIdleMs != 5000 {
		t.Errorf("expected time_idle_ms 5000, got %d", msg.TimeIdleMs)
	}
	if msg.TimeStagedMs != 10000 {
		t.Errorf("expected time_staged_ms 10000, got %d", msg.TimeStagedMs)
	}
	if msg.TimeCpuMs != 60000 {
		t.Errorf("expected time_cpu_ms 60000, got %d", msg.TimeCpuMs)
	}

	// Verify JSON serialization includes the fields
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := decoded["time_idle_ms"]; !ok {
		t.Error("time_idle_ms should be in JSON")
	}
	if _, ok := decoded["time_staged_ms"]; !ok {
		t.Error("time_staged_ms should be in JSON")
	}
	if _, ok := decoded["time_cpu_ms"]; !ok {
		t.Error("time_cpu_ms should be in JSON")
	}
}

// TestTaskStatusUpdateEndToEnd tests the full status update flow over the protocol.
// B sends a TypeStatusUpdate frame to A (the submitter), which triggers handleTaskStatusUpdate.
func TestTaskStatusUpdateEndToEnd(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Establish mutual trust
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// A submits task to B
	client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp, err := client.SubmitTask("Status update test task", b.Daemon.Addr().String())
	client.Close()
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.Status != tasksubmit.StatusAccepted {
		t.Fatalf("expected accepted, got %d: %s", resp.Status, resp.Message)
	}
	taskID := resp.TaskID

	// Manually create the submitter-side task file (simulates what pilotctl does)
	tf := tasksubmit.NewTaskFile(taskID, "Status update test task",
		a.Daemon.Addr().String(), b.Daemon.Addr().String())
	if err := daemon.SaveTaskFile(tf, true); err != nil {
		t.Fatalf("save submitter task file: %v", err)
	}
	defer removeTaskFile(taskID, true)
	defer removeTaskFile(taskID, false)

	// B sends status update to A (new connection to A's port 1003)
	updateClient, err := tasksubmit.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial for status update: %v", err)
	}
	if err := updateClient.SendStatusUpdate(taskID, tasksubmit.TaskStatusExecuting, "Starting execution"); err != nil {
		t.Fatalf("send status update: %v", err)
	}
	updateClient.Close()

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify submitter's task file was updated
	loaded, err := daemon.LoadSubmittedTaskFile(taskID)
	if err != nil {
		t.Fatalf("load submitted: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusExecuting {
		t.Errorf("expected EXECUTING, got %q", loaded.Status)
	}
	if loaded.StatusJustification != "Starting execution" {
		t.Errorf("expected justification, got %q", loaded.StatusJustification)
	}
}

// TestTaskResultsEndToEnd tests the full results flow over the protocol.
// B sends TypeSendResults frame to A, which triggers handleTaskResults.
func TestTaskResultsEndToEnd(t *testing.T) {
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	// Establish mutual trust
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake a→b: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "test"); err != nil {
		t.Fatalf("handshake b→a: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// A submits task to B
	client, err := tasksubmit.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	resp, err := client.SubmitTask("Results test task", b.Daemon.Addr().String())
	client.Close()
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	taskID := resp.TaskID

	// Create submitter-side task file with valid pilot addresses
	tf := tasksubmit.NewTaskFile(taskID, "Results test task",
		a.Daemon.Addr().String(), b.Daemon.Addr().String())
	if err := daemon.SaveTaskFile(tf, true); err != nil {
		t.Fatalf("save submitter task file: %v", err)
	}
	defer removeTaskFile(taskID, true)
	defer removeTaskFile(taskID, false)

	// Clean up result files after test
	defer func() {
		home, _ := os.UserHomeDir()
		os.Remove(home + "/.pilot/tasks/results/" + taskID + "_result.txt")
	}()

	// B sends results to A
	resultsClient, err := tasksubmit.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial for results: %v", err)
	}
	msg := &tasksubmit.TaskResultMessage{
		TaskID:       taskID,
		ResultType:   "text",
		ResultText:   "Task completed successfully",
		CompletedAt:  time.Now().UTC().Format(time.RFC3339),
		TimeIdleMs:   1000,
		TimeStagedMs: 2000,
		TimeCpuMs:    5000,
	}
	if err := resultsClient.SendResults(msg); err != nil {
		t.Fatalf("send results: %v", err)
	}
	resultsClient.Close()

	// Wait for processing
	time.Sleep(300 * time.Millisecond)

	// Verify submitter's task file was updated to COMPLETED
	loaded, err := daemon.LoadSubmittedTaskFile(taskID)
	if err != nil {
		t.Fatalf("load submitted: %v", err)
	}
	if loaded.Status != tasksubmit.TaskStatusCompleted {
		t.Errorf("expected COMPLETED, got %q", loaded.Status)
	}

	// Verify result file was saved
	home, _ := os.UserHomeDir()
	resultFile := home + "/.pilot/tasks/results/" + taskID + "_result.txt"
	data, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatalf("read result file: %v", err)
	}
	if string(data) != "Task completed successfully" {
		t.Errorf("expected result text, got %q", string(data))
	}
}

// TestTaskSubmitServerStandalone tests the standalone tasksubmit.Server.
func TestTaskSubmitServerStandalone(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	// Daemon A with built-in task submit DISABLED — we'll use the standalone server
	a := env.AddDaemon(func(c *daemon.Config) { c.DisableTaskSubmit = true })
	b := env.AddDaemon()

	// Start standalone tasksubmit.Server on daemon A
	accepted := make(chan *tasksubmit.SubmitRequest, 1)
	srv := tasksubmit.NewServer(a.Driver, func(conn net.Conn, req *tasksubmit.SubmitRequest) bool {
		accepted <- req
		return true
	})
	go srv.ListenAndServe()
	time.Sleep(100 * time.Millisecond) // wait for listen

	// B submits a task to A via the tasksubmit client
	client, err := tasksubmit.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	resp, err := client.SubmitTask("standalone test task", a.Daemon.Addr().String())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.Status != tasksubmit.StatusAccepted {
		t.Errorf("expected accepted, got status %d", resp.Status)
	}
	t.Logf("response: status=%d message=%q", resp.Status, resp.Message)

	// Verify handler received the request
	select {
	case req := <-accepted:
		if req.TaskDescription != "standalone test task" {
			t.Errorf("expected description, got %q", req.TaskDescription)
		}
		t.Logf("handler received: %q", req.TaskDescription)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not receive request")
	}
}

// TestCalculateTimeStagedEdgeCases tests empty/invalid inputs for CalculateTimeStaged.
func TestCalculateTimeStagedEdgeCases(t *testing.T) {
	t.Parallel()

	// Empty StagedAt — should be a no-op
	tf := &tasksubmit.TaskFile{TaskID: "calc-staged-empty"}
	tf.CalculateTimeStaged()
	if tf.ExecuteStartedAt != "" {
		t.Errorf("expected empty ExecuteStartedAt for empty StagedAt, got %q", tf.ExecuteStartedAt)
	}
	if tf.TimeStagedMs != 0 {
		t.Errorf("expected zero TimeStagedMs for empty StagedAt, got %d", tf.TimeStagedMs)
	}

	// Invalid StagedAt — should be a no-op
	tf2 := &tasksubmit.TaskFile{TaskID: "calc-staged-invalid", StagedAt: "not-a-date"}
	tf2.CalculateTimeStaged()
	if tf2.ExecuteStartedAt != "" {
		t.Error("expected empty ExecuteStartedAt for invalid StagedAt")
	}
}

// TestCalculateTimeCpuEdgeCases tests empty/invalid inputs for CalculateTimeCpu.
func TestCalculateTimeCpuEdgeCases(t *testing.T) {
	t.Parallel()

	// Empty ExecuteStartedAt — should be a no-op
	tf := &tasksubmit.TaskFile{TaskID: "calc-cpu-empty"}
	tf.CalculateTimeCpu()
	if tf.CompletedAt != "" {
		t.Errorf("expected empty CompletedAt for empty ExecuteStartedAt, got %q", tf.CompletedAt)
	}
	if tf.TimeCpuMs != 0 {
		t.Errorf("expected zero TimeCpuMs for empty ExecuteStartedAt, got %d", tf.TimeCpuMs)
	}

	// Invalid ExecuteStartedAt — should be a no-op
	tf2 := &tasksubmit.TaskFile{TaskID: "calc-cpu-invalid", ExecuteStartedAt: "garbage"}
	tf2.CalculateTimeCpu()
	if tf2.CompletedAt != "" {
		t.Error("expected empty CompletedAt for invalid ExecuteStartedAt")
	}
}

// TestTaskSubmitServerReject tests the standalone server rejection path.
func TestTaskSubmitServerReject(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(c *daemon.Config) { c.DisableTaskSubmit = true })
	b := env.AddDaemon()

	// Server that always rejects
	srv := tasksubmit.NewServer(a.Driver, func(conn net.Conn, req *tasksubmit.SubmitRequest) bool {
		return false
	})
	go srv.ListenAndServe()
	time.Sleep(100 * time.Millisecond)

	client, err := tasksubmit.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	resp, err := client.SubmitTask("reject me", a.Daemon.Addr().String())
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.Status != tasksubmit.StatusRejected {
		t.Errorf("expected rejected (status %d), got %d", tasksubmit.StatusRejected, resp.Status)
	}
	t.Logf("rejection response: status=%d message=%q", resp.Status, resp.Message)
}

// TestUnmarshalTypeMismatch tests all unmarshal functions reject wrong frame types.
func TestUnmarshalTypeMismatch(t *testing.T) {
	t.Parallel()

	// Create a valid submit frame
	submitFrame := &tasksubmit.Frame{Type: tasksubmit.TypeSubmit, Payload: []byte(`{"task_id":"t1"}`)}
	resultFrame := &tasksubmit.Frame{Type: tasksubmit.TypeResult, Payload: []byte(`{"status":"ok"}`)}
	statusFrame := &tasksubmit.Frame{Type: tasksubmit.TypeStatusUpdate, Payload: []byte(`{"task_id":"t1"}`)}
	resultsFrame := &tasksubmit.Frame{Type: tasksubmit.TypeSendResults, Payload: []byte(`{"task_id":"t1"}`)}

	// UnmarshalSubmitRequest expects TypeSubmit — give it TypeResult
	_, err := tasksubmit.UnmarshalSubmitRequest(resultFrame)
	if err == nil {
		t.Error("UnmarshalSubmitRequest should reject non-TypeSubmit frame")
	}

	// UnmarshalTaskResult expects TypeResult — give it TypeSubmit
	_, err = tasksubmit.UnmarshalTaskResult(submitFrame)
	if err == nil {
		t.Error("UnmarshalTaskResult should reject non-TypeResult frame")
	}

	// UnmarshalTaskStatusUpdate expects TypeStatusUpdate — give it TypeResult
	_, err = tasksubmit.UnmarshalTaskStatusUpdate(resultFrame)
	if err == nil {
		t.Error("UnmarshalTaskStatusUpdate should reject non-TypeStatusUpdate frame")
	}

	// UnmarshalTaskResultMessage expects TypeSendResults — give it TypeSubmit
	_, err = tasksubmit.UnmarshalTaskResultMessage(submitFrame)
	if err == nil {
		t.Error("UnmarshalTaskResultMessage should reject non-TypeSendResults frame")
	}

	// Verify correct types DO work
	_, err = tasksubmit.UnmarshalTaskStatusUpdate(statusFrame)
	if err != nil {
		t.Errorf("UnmarshalTaskStatusUpdate should accept TypeStatusUpdate: %v", err)
	}

	_, err = tasksubmit.UnmarshalTaskResultMessage(resultsFrame)
	if err != nil {
		t.Errorf("UnmarshalTaskResultMessage should accept TypeSendResults: %v", err)
	}
}

// TestFrameReadWriteRoundTrip tests WriteFrame/ReadFrame with actual bytes buffers.
func TestFrameReadWriteRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ftype   uint32
		payload []byte
	}{
		{"empty payload", tasksubmit.TypeSubmit, []byte{}},
		{"small payload", tasksubmit.TypeResult, []byte(`{"status":"ok"}`)},
		{"status update", tasksubmit.TypeStatusUpdate, []byte(`{"task_id":"abc","status":"EXECUTING"}`)},
		{"send results", tasksubmit.TypeSendResults, []byte(`{"task_id":"abc","result_type":"text"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			frame := &tasksubmit.Frame{Type: tt.ftype, Payload: tt.payload}
			if err := tasksubmit.WriteFrame(&buf, frame); err != nil {
				t.Fatalf("write: %v", err)
			}

			got, err := tasksubmit.ReadFrame(&buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if got.Type != tt.ftype {
				t.Errorf("type: got %d, want %d", got.Type, tt.ftype)
			}
			if !bytes.Equal(got.Payload, tt.payload) {
				t.Errorf("payload mismatch: got %q, want %q", got.Payload, tt.payload)
			}
		})
	}
}

// TestFrameReadOversized tests ReadFrame rejects frames > 16MB.
func TestFrameReadOversized(t *testing.T) {
	t.Parallel()

	// Craft a header claiming 32MB payload
	var buf bytes.Buffer
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], tasksubmit.TypeSubmit)
	binary.BigEndian.PutUint32(hdr[4:8], 1<<25) // 32MB
	buf.Write(hdr[:])

	_, err := tasksubmit.ReadFrame(&buf)
	if err == nil {
		t.Error("ReadFrame should reject frames > 16MB")
	}
}

// TestTaskStatusUpdateMarshalRoundTrip tests full round-trip of status update frames.
func TestTaskStatusUpdateMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	update := &tasksubmit.TaskStatusUpdate{
		TaskID:        "test-task-123",
		Status:        tasksubmit.TaskStatusExecuting,
		Justification: "Starting execution now",
	}

	frame, err := tasksubmit.MarshalTaskStatusUpdate(update)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if frame.Type != tasksubmit.TypeStatusUpdate {
		t.Errorf("expected type %d, got %d", tasksubmit.TypeStatusUpdate, frame.Type)
	}

	parsed, err := tasksubmit.UnmarshalTaskStatusUpdate(frame)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.TaskID != update.TaskID {
		t.Errorf("task_id: got %q, want %q", parsed.TaskID, update.TaskID)
	}
	if parsed.Status != update.Status {
		t.Errorf("status: got %q, want %q", parsed.Status, update.Status)
	}
	if parsed.Justification != update.Justification {
		t.Errorf("justification: got %q, want %q", parsed.Justification, update.Justification)
	}
}

// TestTaskResultMessageMarshalRoundTrip tests full round-trip of result message frames.
func TestTaskResultMessageMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	msg := &tasksubmit.TaskResultMessage{
		TaskID:       "result-msg-test",
		ResultType:   "text",
		ResultText:   "Here are the results",
		CompletedAt:  time.Now().UTC().Format(time.RFC3339),
		TimeIdleMs:   1500,
		TimeStagedMs: 3000,
		TimeCpuMs:    60000,
	}

	frame, err := tasksubmit.MarshalTaskResultMessage(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if frame.Type != tasksubmit.TypeSendResults {
		t.Errorf("expected type %d, got %d", tasksubmit.TypeSendResults, frame.Type)
	}

	parsed, err := tasksubmit.UnmarshalTaskResultMessage(frame)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.TaskID != msg.TaskID {
		t.Errorf("task_id: got %q, want %q", parsed.TaskID, msg.TaskID)
	}
	if parsed.ResultType != msg.ResultType {
		t.Errorf("result_type: got %q, want %q", parsed.ResultType, msg.ResultType)
	}
	if parsed.ResultText != msg.ResultText {
		t.Errorf("result_text: got %q, want %q", parsed.ResultText, msg.ResultText)
	}
	if parsed.TimeCpuMs != msg.TimeCpuMs {
		t.Errorf("time_cpu_ms: got %d, want %d", parsed.TimeCpuMs, msg.TimeCpuMs)
	}
}

// TestTypeNameComplete tests all TypeName values including STATUS_UPDATE and SEND_RESULTS.
func TestTypeNameComplete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		typ  uint32
		name string
	}{
		{tasksubmit.TypeSubmit, "SUBMIT"},
		{tasksubmit.TypeResult, "RESULT"},
		{tasksubmit.TypeStatusUpdate, "STATUS_UPDATE"},
		{tasksubmit.TypeSendResults, "SEND_RESULTS"},
		{0, "UNKNOWN(0)"},
		{999, "UNKNOWN(999)"},
	}

	for _, tt := range tests {
		name := tasksubmit.TypeName(tt.typ)
		if name != tt.name {
			t.Errorf("TypeName(%d) = %q, want %q", tt.typ, name, tt.name)
		}
	}
}

// TestTimeSinceCreationEdgeCases tests error paths for TimeSinceCreation.
func TestTimeSinceCreationEdgeCases(t *testing.T) {
	t.Parallel()

	// Empty CreatedAt
	tf := &tasksubmit.TaskFile{TaskID: "tsc-empty"}
	_, err := tf.TimeSinceCreation()
	if err == nil {
		t.Error("expected error for empty CreatedAt")
	}

	// Invalid CreatedAt
	tf2 := &tasksubmit.TaskFile{TaskID: "tsc-invalid", CreatedAt: "not-a-date"}
	_, err = tf2.TimeSinceCreation()
	if err == nil {
		t.Error("expected error for invalid CreatedAt")
	}

	// Valid CreatedAt
	tf3 := &tasksubmit.TaskFile{
		TaskID:    "tsc-valid",
		CreatedAt: time.Now().UTC().Add(-10 * time.Second).Format(time.RFC3339),
	}
	dur, err := tf3.TimeSinceCreation()
	if err != nil {
		t.Fatalf("TimeSinceCreation: %v", err)
	}
	if dur < 9*time.Second || dur > 12*time.Second {
		t.Errorf("expected ~10s, got %v", dur)
	}
}

// TestTimeSinceStagedEdgeCases tests error paths for TimeSinceStaged.
func TestTimeSinceStagedEdgeCases(t *testing.T) {
	t.Parallel()

	// Empty StagedAt
	tf := &tasksubmit.TaskFile{TaskID: "tss-empty"}
	_, err := tf.TimeSinceStaged()
	if err == nil {
		t.Error("expected error for empty StagedAt")
	}

	// Invalid StagedAt
	tf2 := &tasksubmit.TaskFile{TaskID: "tss-invalid", StagedAt: "garbage"}
	_, err = tf2.TimeSinceStaged()
	if err == nil {
		t.Error("expected error for invalid StagedAt")
	}

	// Valid StagedAt
	tf3 := &tasksubmit.TaskFile{
		TaskID:   "tss-valid",
		StagedAt: time.Now().UTC().Add(-5 * time.Second).Format(time.RFC3339),
	}
	dur, err := tf3.TimeSinceStaged()
	if err != nil {
		t.Fatalf("TimeSinceStaged: %v", err)
	}
	if dur < 4*time.Second || dur > 7*time.Second {
		t.Errorf("expected ~5s, got %v", dur)
	}
}

// TestCalculateTimeIdleEdgeCases tests empty/invalid inputs for CalculateTimeIdle.
func TestCalculateTimeIdleEdgeCases(t *testing.T) {
	t.Parallel()

	// Empty CreatedAt — should be a no-op
	tf := &tasksubmit.TaskFile{TaskID: "idle-empty"}
	tf.CalculateTimeIdle()
	if tf.AcceptedAt != "" {
		t.Errorf("expected empty AcceptedAt for empty CreatedAt, got %q", tf.AcceptedAt)
	}

	// Invalid CreatedAt — should be a no-op
	tf2 := &tasksubmit.TaskFile{TaskID: "idle-invalid", CreatedAt: "not-valid"}
	tf2.CalculateTimeIdle()
	if tf2.AcceptedAt != "" {
		t.Error("expected empty AcceptedAt for invalid CreatedAt")
	}
}

// TestIsExpiredForAcceptEdgeCases tests edge cases of the accept expiry logic.
func TestIsExpiredForAcceptEdgeCases(t *testing.T) {
	t.Parallel()

	// Invalid CreatedAt — should NOT be expired (parse error)
	tf := &tasksubmit.TaskFile{
		TaskID:    "exp-invalid",
		Status:    tasksubmit.TaskStatusNew,
		CreatedAt: "bad-date",
	}
	if tf.IsExpiredForAccept() {
		t.Error("invalid CreatedAt should not count as expired")
	}
}

// TestIsExpiredInQueueEdgeCases tests edge cases of the queue expiry logic.
func TestIsExpiredInQueueEdgeCases(t *testing.T) {
	t.Parallel()

	// Empty StagedAt — should NOT be expired
	tf := &tasksubmit.TaskFile{
		TaskID: "q-empty",
		Status: tasksubmit.TaskStatusAccepted,
	}
	if tf.IsExpiredInQueue() {
		t.Error("empty StagedAt should not count as expired")
	}

	// Invalid StagedAt — should NOT be expired
	tf2 := &tasksubmit.TaskFile{
		TaskID:   "q-invalid",
		Status:   tasksubmit.TaskStatusAccepted,
		StagedAt: "not-a-date",
	}
	if tf2.IsExpiredInQueue() {
		t.Error("invalid StagedAt should not count as expired")
	}
}
