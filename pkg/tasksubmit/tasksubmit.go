package tasksubmit

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"time"
)

// Status codes for task submission responses.
const (
	StatusAccepted = 200
	StatusRejected = 400
)

// Task statuses
const (
	TaskStatusNew       = "NEW"
	TaskStatusAccepted  = "ACCEPTED"
	TaskStatusDeclined  = "DECLINED"
	TaskStatusExecuting = "EXECUTING"
	TaskStatusCompleted = "COMPLETED"
	TaskStatusSucceeded = "SUCCEEDED"
	TaskStatusCancelled = "CANCELLED"
	TaskStatusExpired   = "EXPIRED"
)

// Task timeout constants
const (
	// TaskAcceptTimeout is the maximum time a task can stay in NEW status before being cancelled
	TaskAcceptTimeout = 1 * time.Minute
	// TaskQueueHeadTimeout is the maximum time a task can stay at the head of the queue before expiring
	TaskQueueHeadTimeout = 1 * time.Hour
)

// Frame types for task submission on port 1003.
const (
	TypeSubmit       uint32 = 1 // Task submission request
	TypeResult       uint32 = 2 // Task result response
	TypeStatusUpdate uint32 = 3 // Task status update (accept/decline/execute/complete)
	TypeSendResults  uint32 = 4 // Send task results
)

// Allowed file extensions for results
var AllowedResultExtensions = map[string]bool{
	// Text files
	".md": true, ".txt": true, ".rtf": true, ".docx": true, ".pdf": true, ".pptx": true,
	// ML model weights
	".pth": true, ".pt": true, ".onnx": true, ".h5": true, ".pb": true, ".ckpt": true,
	".safetensors": true, ".bin": true,
	// Datasets
	".csv": true, ".parquet": true, ".xlsx": true, ".xls": true,
	// Images
	".jpg": true, ".jpeg": true, ".png": true, ".svg": true, ".gif": true, ".webp": true,
}

// Forbidden file extensions (source code)
var ForbiddenResultExtensions = map[string]bool{
	".go": true, ".py": true, ".js": true, ".ts": true, ".java": true, ".c": true,
	".cpp": true, ".h": true, ".hpp": true, ".rs": true, ".rb": true, ".php": true,
	".swift": true, ".kt": true, ".scala": true, ".sh": true, ".bash": true, ".zsh": true,
	".ps1": true, ".bat": true, ".cmd": true, ".sql": true, ".r": true, ".R": true,
	".lua": true, ".pl": true, ".pm": true, ".ex": true, ".exs": true, ".clj": true,
	".hs": true, ".ml": true, ".fs": true, ".cs": true, ".vb": true, ".dart": true,
}

// SubmitRequest represents a task submission request.
type SubmitRequest struct {
	TaskID          string `json:"task_id"`
	TaskDescription string `json:"task_description"`
	FromAddr        string `json:"from_addr"`
	ToAddr          string `json:"to_addr"`
}

// SubmitResponse represents the response to a task submission.
type SubmitResponse struct {
	TaskID  string `json:"task_id"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// TaskFile represents a task stored on disk.
type TaskFile struct {
	TaskID              string `json:"task_id"`
	TaskDescription     string `json:"task_description"`
	CreatedAt           string `json:"created_at"`
	Status              string `json:"status"`
	StatusJustification string `json:"status_justification"`
	From                string `json:"from"`
	To                  string `json:"to"`

	// Time metadata tracking
	AcceptedAt       string `json:"accepted_at,omitempty"`        // When task was accepted/declined
	StagedAt         string `json:"staged_at,omitempty"`          // When task became head of queue
	ExecuteStartedAt string `json:"execute_started_at,omitempty"` // When pilotctl execute was called
	CompletedAt      string `json:"completed_at,omitempty"`       // When results were sent

	// Computed durations (in milliseconds for precision)
	TimeIdleMs   int64 `json:"time_idle_ms,omitempty"`   // Time from creation to accept/decline
	TimeStagedMs int64 `json:"time_staged_ms,omitempty"` // Time at head of queue before execute
	TimeCpuMs    int64 `json:"time_cpu_ms,omitempty"`    // Time spent executing before sending results
}

// TaskStatusUpdate represents a status change message.
type TaskStatusUpdate struct {
	TaskID        string `json:"task_id"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// TaskResultMessage represents task results being sent back.
type TaskResultMessage struct {
	TaskID      string `json:"task_id"`
	ResultType  string `json:"result_type"` // "text" or "file"
	ResultText  string `json:"result_text,omitempty"`
	Filename    string `json:"filename,omitempty"`
	FileData    []byte `json:"file_data,omitempty"`
	CompletedAt string `json:"completed_at"`

	// Time metadata for polo score calculation
	TimeIdleMs   int64 `json:"time_idle_ms,omitempty"`   // Time from creation to accept/decline
	TimeStagedMs int64 `json:"time_staged_ms,omitempty"` // Time at head of queue before execute
	TimeCpuMs    int64 `json:"time_cpu_ms,omitempty"`    // Time spent executing before sending results
}

// TaskResult represents the result of a completed task (legacy compatibility).
type TaskResult struct {
	TaskDescription string      `json:"task_description"`
	Status          string      `json:"status"` // "success" or "error"
	Result          interface{} `json:"result"` // can be string, object, etc.
	Error           string      `json:"error,omitempty"`
	Timestamp       string      `json:"timestamp"`
}

// GenerateTaskID generates a unique task ID using crypto/rand.
// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (UUID-like format)
func GenerateTaskID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewTaskFile creates a new TaskFile with NEW status.
func NewTaskFile(taskID, taskDescription, fromAddr, toAddr string) *TaskFile {
	return &TaskFile{
		TaskID:              taskID,
		TaskDescription:     taskDescription,
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		Status:              TaskStatusNew,
		StatusJustification: "A new task was created",
		From:                fromAddr,
		To:                  toAddr,
	}
}

// ParseTime parses a time string in RFC3339 format.
func ParseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// TimeSinceCreation returns the duration since the task was created.
func (tf *TaskFile) TimeSinceCreation() (time.Duration, error) {
	created, err := ParseTime(tf.CreatedAt)
	if err != nil {
		return 0, err
	}
	return time.Since(created), nil
}

// IsExpiredForAccept checks if the task has exceeded the accept timeout (1 minute).
func (tf *TaskFile) IsExpiredForAccept() bool {
	if tf.Status != TaskStatusNew {
		return false
	}
	dur, err := tf.TimeSinceCreation()
	if err != nil {
		return false
	}
	return dur > TaskAcceptTimeout
}

// CalculateTimeIdle calculates and sets time_idle_ms based on creation and current time.
func (tf *TaskFile) CalculateTimeIdle() {
	created, err := ParseTime(tf.CreatedAt)
	if err != nil {
		slog.Warn("tasksubmit: failed to parse created_at for idle calculation", "task_id", tf.TaskID, "error", err)
		return
	}
	now := time.Now().UTC()
	tf.AcceptedAt = now.Format(time.RFC3339)
	tf.TimeIdleMs = now.Sub(created).Milliseconds()
}

// CalculateTimeStaged calculates and sets time_staged_ms based on staged time and current time.
func (tf *TaskFile) CalculateTimeStaged() {
	if tf.StagedAt == "" {
		slog.Debug("tasksubmit: staged_at not set, skipping staged calculation", "task_id", tf.TaskID)
		return
	}
	staged, err := ParseTime(tf.StagedAt)
	if err != nil {
		slog.Warn("tasksubmit: failed to parse staged_at for staged calculation", "task_id", tf.TaskID, "error", err)
		return
	}
	now := time.Now().UTC()
	tf.ExecuteStartedAt = now.Format(time.RFC3339)
	tf.TimeStagedMs = now.Sub(staged).Milliseconds()
}

// CalculateTimeCpu calculates and sets time_cpu_ms based on execute start and current time.
func (tf *TaskFile) CalculateTimeCpu() {
	if tf.ExecuteStartedAt == "" {
		slog.Debug("tasksubmit: execute_started_at not set, skipping CPU calculation", "task_id", tf.TaskID)
		return
	}
	started, err := ParseTime(tf.ExecuteStartedAt)
	if err != nil {
		slog.Warn("tasksubmit: failed to parse execute_started_at for CPU calculation", "task_id", tf.TaskID, "error", err)
		return
	}
	now := time.Now().UTC()
	tf.CompletedAt = now.Format(time.RFC3339)
	tf.TimeCpuMs = now.Sub(started).Milliseconds()
}

// TimeSinceStaged returns the duration since the task was staged (became head of queue).
func (tf *TaskFile) TimeSinceStaged() (time.Duration, error) {
	if tf.StagedAt == "" {
		return 0, fmt.Errorf("task not yet staged")
	}
	staged, err := ParseTime(tf.StagedAt)
	if err != nil {
		return 0, err
	}
	return time.Since(staged), nil
}

// IsExpiredInQueue checks if the task has exceeded the queue head timeout (1 hour).
func (tf *TaskFile) IsExpiredInQueue() bool {
	if tf.Status != TaskStatusAccepted {
		return false
	}
	dur, err := tf.TimeSinceStaged()
	if err != nil {
		return false
	}
	return dur > TaskQueueHeadTimeout
}

// PoloScoreReward calculates the polo score reward for a successfully completed task.
//
// The formula uses logarithmic scaling for compute time and proportional penalties
// for responsiveness, creating a balanced reward system:
//
//	reward = (base + cpuBonus) * efficiencyMultiplier
//
// Components:
//   - base = 1.0 (guaranteed minimum for completing any task)
//   - cpuBonus = log2(1 + cpu_minutes) (logarithmic scaling, no cap)
//   - 1 min → +1.0, 3 min → +2.0, 7 min → +3.0, 15 min → +4.0, 31 min → +5.0
//   - efficiencyMultiplier = 1.0 - idleFactor - stagedFactor
//   - idleFactor = min(time_idle / 60s, 0.3) (up to 30% penalty for slow accept)
//   - stagedFactor = min(time_staged / 600s, 0.3) (up to 30% penalty for queue delays)
//
// The efficiency multiplier ranges from 0.4 to 1.0, rewarding responsive agents.
// Final reward is rounded to nearest integer with minimum of 1.
//
// Examples:
//   - Instant accept, instant execute, 1 min CPU → (1+1.0)*1.0 = 2
//   - Instant accept, instant execute, 10 min CPU → (1+3.46)*1.0 = 4
//   - 30s idle, 5 min staged, 10 min CPU → (1+3.46)*0.55 = 2
//   - Instant accept, instant execute, 30 min CPU → (1+4.95)*1.0 = 6
func (tf *TaskFile) PoloScoreReward() int {
	return tf.PoloScoreRewardDetailed().FinalReward
}

// PoloScoreBreakdown contains the detailed breakdown of the polo score calculation.
type PoloScoreBreakdown struct {
	Base                 float64 `json:"base"`
	CpuBonus             float64 `json:"cpu_bonus"`
	CpuMinutes           float64 `json:"cpu_minutes"`
	IdleFactor           float64 `json:"idle_factor"`
	StagedFactor         float64 `json:"staged_factor"`
	EfficiencyMultiplier float64 `json:"efficiency_multiplier"`
	RawReward            float64 `json:"raw_reward"`
	FinalReward          int     `json:"final_reward"`
}

// PoloScoreRewardDetailed calculates and returns the detailed polo score breakdown.
func (tf *TaskFile) PoloScoreRewardDetailed() PoloScoreBreakdown {
	const (
		baseReward = 1.0

		// Idle penalty: scales linearly up to 60 seconds, max 30% penalty
		maxIdleSeconds = 60.0
		maxIdleFactor  = 0.3

		// Staged penalty: scales linearly up to 10 minutes, max 30% penalty
		maxStagedSeconds = 600.0
		maxStagedFactor  = 0.3
	)

	// Calculate CPU bonus using log2(1 + minutes)
	// This gives diminishing returns but no hard cap:
	// 1 min → 1.0, 3 min → 2.0, 7 min → 3.0, 15 min → 4.0, 31 min → 5.0, 63 min → 6.0
	cpuMinutes := float64(tf.TimeCpuMs) / 60000.0
	cpuBonus := math.Log2(1.0 + cpuMinutes)

	// Calculate idle factor (0.0 to 0.3)
	// Agents should accept/decline within seconds, penalty grows over 60 seconds
	idleSeconds := float64(tf.TimeIdleMs) / 1000.0
	idleFactor := (idleSeconds / maxIdleSeconds) * maxIdleFactor
	if idleFactor > maxIdleFactor {
		idleFactor = maxIdleFactor
	}
	if idleFactor < 0 {
		idleFactor = 0
	}

	// Calculate staged factor (0.0 to 0.3)
	// Tasks should be executed reasonably quickly, penalty grows over 10 minutes
	stagedSeconds := float64(tf.TimeStagedMs) / 1000.0
	stagedFactor := (stagedSeconds / maxStagedSeconds) * maxStagedFactor
	if stagedFactor > maxStagedFactor {
		stagedFactor = maxStagedFactor
	}
	if stagedFactor < 0 {
		stagedFactor = 0
	}

	// Efficiency multiplier: 1.0 = perfect responsiveness, 0.4 = max penalties
	efficiencyMultiplier := 1.0 - idleFactor - stagedFactor
	if efficiencyMultiplier < 0.4 {
		efficiencyMultiplier = 0.4
	}

	// Calculate raw reward
	rawReward := (baseReward + cpuBonus) * efficiencyMultiplier

	// Final reward: round to nearest integer, minimum 1
	finalReward := int(rawReward + 0.5)
	if finalReward < 1 {
		finalReward = 1
	}

	return PoloScoreBreakdown{
		Base:                 baseReward,
		CpuBonus:             cpuBonus,
		CpuMinutes:           cpuMinutes,
		IdleFactor:           idleFactor,
		StagedFactor:         stagedFactor,
		EfficiencyMultiplier: efficiencyMultiplier,
		RawReward:            rawReward,
		FinalReward:          finalReward,
	}
}

// Frame is a typed data unit exchanged for task submissions.
// Wire format: [4-byte type][4-byte length][JSON payload]
type Frame struct {
	Type    uint32
	Payload []byte
}

// WriteFrame writes a frame to a writer.
func WriteFrame(w io.Writer, f *Frame) error {
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], f.Type)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}

// ReadFrame reads a frame from a reader.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	ftype := binary.BigEndian.Uint32(hdr[0:4])
	length := binary.BigEndian.Uint32(hdr[4:8])
	if length > 1<<24 { // 16MB max
		return nil, fmt.Errorf("frame too large: %d", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return &Frame{Type: ftype, Payload: payload}, nil
}

// TypeName returns a human-readable name for a frame type.
func TypeName(t uint32) string {
	switch t {
	case TypeSubmit:
		return "SUBMIT"
	case TypeResult:
		return "RESULT"
	case TypeStatusUpdate:
		return "STATUS_UPDATE"
	case TypeSendResults:
		return "SEND_RESULTS"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// MarshalSubmitRequest creates a submit frame from a request.
func MarshalSubmitRequest(req *SubmitRequest) (*Frame, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: TypeSubmit, Payload: data}, nil
}

// UnmarshalSubmitRequest parses a submit frame into a request.
func UnmarshalSubmitRequest(f *Frame) (*SubmitRequest, error) {
	if f.Type != TypeSubmit {
		return nil, fmt.Errorf("expected TypeSubmit, got %d", f.Type)
	}
	var req SubmitRequest
	if err := json.Unmarshal(f.Payload, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// MarshalSubmitResponse creates a response frame.
func MarshalSubmitResponse(resp *SubmitResponse) (*Frame, error) {
	data, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: TypeSubmit, Payload: data}, nil
}

// UnmarshalSubmitResponse parses a response frame.
func UnmarshalSubmitResponse(f *Frame) (*SubmitResponse, error) {
	var resp SubmitResponse
	if err := json.Unmarshal(f.Payload, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// MarshalTaskResult creates a result frame.
func MarshalTaskResult(result *TaskResult) (*Frame, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: TypeResult, Payload: data}, nil
}

// UnmarshalTaskResult parses a result frame.
func UnmarshalTaskResult(f *Frame) (*TaskResult, error) {
	if f.Type != TypeResult {
		return nil, fmt.Errorf("expected TypeResult, got %d", f.Type)
	}
	var result TaskResult
	if err := json.Unmarshal(f.Payload, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// MarshalTaskStatusUpdate creates a status update frame.
func MarshalTaskStatusUpdate(update *TaskStatusUpdate) (*Frame, error) {
	data, err := json.Marshal(update)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: TypeStatusUpdate, Payload: data}, nil
}

// UnmarshalTaskStatusUpdate parses a status update frame.
func UnmarshalTaskStatusUpdate(f *Frame) (*TaskStatusUpdate, error) {
	if f.Type != TypeStatusUpdate {
		return nil, fmt.Errorf("expected TypeStatusUpdate, got %d", f.Type)
	}
	var update TaskStatusUpdate
	if err := json.Unmarshal(f.Payload, &update); err != nil {
		return nil, err
	}
	return &update, nil
}

// MarshalTaskResultMessage creates a send results frame.
func MarshalTaskResultMessage(msg *TaskResultMessage) (*Frame, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	return &Frame{Type: TypeSendResults, Payload: data}, nil
}

// UnmarshalTaskResultMessage parses a send results frame.
func UnmarshalTaskResultMessage(f *Frame) (*TaskResultMessage, error) {
	if f.Type != TypeSendResults {
		return nil, fmt.Errorf("expected TypeSendResults, got %d", f.Type)
	}
	var msg TaskResultMessage
	if err := json.Unmarshal(f.Payload, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// MarshalTaskFile serializes a TaskFile to JSON bytes.
func MarshalTaskFile(tf *TaskFile) ([]byte, error) {
	return json.MarshalIndent(tf, "", "  ")
}

// UnmarshalTaskFile deserializes JSON bytes to a TaskFile.
func UnmarshalTaskFile(data []byte) (*TaskFile, error) {
	var tf TaskFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, err
	}
	return &tf, nil
}
