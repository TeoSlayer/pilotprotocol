package tests

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/tasksubmit"
)

// ---------------------------------------------------------------------------
// Fuzz targets
// ---------------------------------------------------------------------------

func FuzzTaskSubmitReadFrame(f *testing.F) {
	// Valid submit frame
	var buf bytes.Buffer
	tasksubmit.WriteFrame(&buf, &tasksubmit.Frame{Type: tasksubmit.TypeSubmit, Payload: []byte(`{"task_id":"1"}`)})
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, 8))
	f.Add(bytes.Repeat([]byte{0xFF}, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = tasksubmit.ReadFrame(r)
	})
}

func FuzzUnmarshalSubmitRequest(f *testing.F) {
	f.Add([]byte(`{"task_id":"abc","task_description":"do something","from_addr":"0:0000.0000.0001","to_addr":"0:0000.0000.0002"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"string"`))
	f.Add([]byte{})
	f.Add([]byte(`{invalid json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		frame := &tasksubmit.Frame{Type: tasksubmit.TypeSubmit, Payload: data}
		_, _ = tasksubmit.UnmarshalSubmitRequest(frame)
	})
}

func FuzzUnmarshalTaskStatusUpdate(f *testing.F) {
	f.Add([]byte(`{"task_id":"1","status":"ACCEPTED","justification":"ok"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		frame := &tasksubmit.Frame{Type: tasksubmit.TypeStatusUpdate, Payload: data}
		_, _ = tasksubmit.UnmarshalTaskStatusUpdate(frame)
	})
}

func FuzzUnmarshalTaskResultMessage(f *testing.F) {
	f.Add([]byte(`{"task_id":"1","result_type":"text","result_text":"done","completed_at":"2024-01-01T00:00:00Z"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		frame := &tasksubmit.Frame{Type: tasksubmit.TypeSendResults, Payload: data}
		_, _ = tasksubmit.UnmarshalTaskResultMessage(frame)
	})
}

func FuzzUnmarshalTaskFile(f *testing.F) {
	f.Add([]byte(`{"task_id":"abc","status":"NEW","created_at":"2024-01-01T00:00:00Z"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte{})
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = tasksubmit.UnmarshalTaskFile(data)
	})
}

func FuzzPoloScore(f *testing.F) {
	f.Add(int64(0), int64(0), int64(0))
	f.Add(int64(60000), int64(0), int64(0))    // 1 min CPU
	f.Add(int64(600000), int64(30000), int64(0)) // 10 min CPU, 30s idle
	f.Add(int64(-1), int64(-1), int64(-1))
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), int64(math.MaxInt64))

	f.Fuzz(func(t *testing.T, cpuMs, idleMs, stagedMs int64) {
		tf := &tasksubmit.TaskFile{
			TimeCpuMs:    cpuMs,
			TimeIdleMs:   idleMs,
			TimeStagedMs: stagedMs,
		}
		reward := tf.PoloScoreReward()
		if reward < 1 {
			t.Fatalf("reward must be >= 1, got %d", reward)
		}
		breakdown := tf.PoloScoreRewardDetailed()
		if math.IsNaN(breakdown.CpuBonus) || math.IsInf(breakdown.CpuBonus, 0) {
			t.Fatalf("CpuBonus is NaN/Inf: %f", breakdown.CpuBonus)
		}
		if math.IsNaN(breakdown.RawReward) || math.IsInf(breakdown.RawReward, 0) {
			t.Fatalf("RawReward is NaN/Inf: %f", breakdown.RawReward)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge case unit tests
// ---------------------------------------------------------------------------

func TestPoloScoreAllZeroTimes(t *testing.T) {
	tf := &tasksubmit.TaskFile{TimeCpuMs: 0, TimeIdleMs: 0, TimeStagedMs: 0}
	reward := tf.PoloScoreReward()
	if reward < 1 {
		t.Fatalf("all-zero reward must be >= 1, got %d", reward)
	}
}

func TestPoloScoreNegativeCpu(t *testing.T) {
	tf := &tasksubmit.TaskFile{TimeCpuMs: -60000, TimeIdleMs: 0, TimeStagedMs: 0}
	reward := tf.PoloScoreReward()
	if reward < 1 {
		t.Fatalf("negative cpu reward must be >= 1, got %d", reward)
	}
	b := tf.PoloScoreRewardDetailed()
	if math.IsNaN(b.CpuBonus) {
		t.Fatal("CpuBonus is NaN for negative CPU")
	}
}

func TestPoloScoreMaxInt64Cpu(t *testing.T) {
	tf := &tasksubmit.TaskFile{TimeCpuMs: math.MaxInt64, TimeIdleMs: 0, TimeStagedMs: 0}
	reward := tf.PoloScoreReward()
	if reward < 1 {
		t.Fatalf("maxint64 cpu reward must be >= 1, got %d", reward)
	}
}

func TestPoloScoreNegativeIdle(t *testing.T) {
	tf := &tasksubmit.TaskFile{TimeCpuMs: 60000, TimeIdleMs: -1, TimeStagedMs: 0}
	b := tf.PoloScoreRewardDetailed()
	if b.IdleFactor != 0 {
		t.Fatalf("negative idle should clamp to 0, got %f", b.IdleFactor)
	}
}

func TestPoloScoreEfficiencyFloor(t *testing.T) {
	// Max penalties: idle = 60s = 0.3, staged = 600s = 0.3
	// Efficiency = 1 - 0.3 - 0.3 = 0.4 (floor)
	tf := &tasksubmit.TaskFile{TimeCpuMs: 60000, TimeIdleMs: 120000, TimeStagedMs: 1200000}
	b := tf.PoloScoreRewardDetailed()
	if b.EfficiencyMultiplier < 0.4 {
		t.Fatalf("efficiency should floor at 0.4, got %f", b.EfficiencyMultiplier)
	}
}

func TestTaskFileMarshalRoundTrip(t *testing.T) {
	tf := &tasksubmit.TaskFile{
		TaskID:          "test-id",
		TaskDescription: "test desc",
		CreatedAt:       "2024-01-01T00:00:00Z",
		Status:          tasksubmit.TaskStatusNew,
		From:            "0:0000.0000.0001",
		To:              "0:0000.0000.0002",
	}
	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		t.Fatalf("MarshalTaskFile: %v", err)
	}
	got, err := tasksubmit.UnmarshalTaskFile(data)
	if err != nil {
		t.Fatalf("UnmarshalTaskFile: %v", err)
	}
	if got.TaskID != tf.TaskID || got.Status != tf.Status || got.From != tf.From {
		t.Fatal("round-trip mismatch")
	}
}

func TestTaskFileEmptyFields(t *testing.T) {
	tf := &tasksubmit.TaskFile{}
	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		t.Fatalf("MarshalTaskFile empty: %v", err)
	}
	got, err := tasksubmit.UnmarshalTaskFile(data)
	if err != nil {
		t.Fatalf("UnmarshalTaskFile empty: %v", err)
	}
	if got.TaskID != "" || got.Status != "" {
		t.Fatal("empty fields should stay empty")
	}
}

func TestTaskFileAllFieldsPopulated(t *testing.T) {
	tf := &tasksubmit.TaskFile{
		TaskID:              "id",
		TaskDescription:     "desc",
		CreatedAt:           "2024-01-01T00:00:00Z",
		Status:              tasksubmit.TaskStatusCompleted,
		StatusJustification: "done",
		From:                "0:0000.0000.0001",
		To:                  "0:0000.0000.0002",
		AcceptedAt:          "2024-01-01T00:00:01Z",
		StagedAt:            "2024-01-01T00:00:02Z",
		ExecuteStartedAt:    "2024-01-01T00:00:03Z",
		CompletedAt:         "2024-01-01T00:00:04Z",
		TimeIdleMs:          1000,
		TimeStagedMs:        1000,
		TimeCpuMs:           1000,
	}
	data, err := tasksubmit.MarshalTaskFile(tf)
	if err != nil {
		t.Fatalf("MarshalTaskFile: %v", err)
	}
	got, err := tasksubmit.UnmarshalTaskFile(data)
	if err != nil {
		t.Fatalf("UnmarshalTaskFile: %v", err)
	}
	if got.AcceptedAt != tf.AcceptedAt || got.TimeCpuMs != tf.TimeCpuMs {
		t.Fatal("populated fields round-trip mismatch")
	}
}

func TestGenerateTaskIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := tasksubmit.GenerateTaskID()
		if ids[id] {
			t.Fatalf("duplicate task ID: %s", id)
		}
		ids[id] = true
	}
}

func TestAllowedForbiddenExtensions(t *testing.T) {
	// Spot-check some allowed extensions
	for _, ext := range []string{".md", ".csv", ".png", ".pth", ".safetensors"} {
		if !tasksubmit.AllowedResultExtensions[ext] {
			t.Errorf("expected %s to be allowed", ext)
		}
	}
	// Spot-check some forbidden extensions
	for _, ext := range []string{".go", ".py", ".js", ".sh", ".sql"} {
		if !tasksubmit.ForbiddenResultExtensions[ext] {
			t.Errorf("expected %s to be forbidden", ext)
		}
	}
	// Ensure no overlap
	for ext := range tasksubmit.AllowedResultExtensions {
		if tasksubmit.ForbiddenResultExtensions[ext] {
			t.Errorf("extension %s is both allowed and forbidden", ext)
		}
	}
}

func TestTaskSubmitTypeName(t *testing.T) {
	cases := map[uint32]string{
		tasksubmit.TypeSubmit:       "SUBMIT",
		tasksubmit.TypeResult:       "RESULT",
		tasksubmit.TypeStatusUpdate: "STATUS_UPDATE",
		tasksubmit.TypeSendResults:  "SEND_RESULTS",
		99:                          "UNKNOWN(99)",
	}
	for k, v := range cases {
		if tasksubmit.TypeName(k) != v {
			t.Errorf("TypeName(%d) = %q, want %q", k, tasksubmit.TypeName(k), v)
		}
	}
}

func TestUnmarshalSubmitRequestWrongType(t *testing.T) {
	frame := &tasksubmit.Frame{Type: tasksubmit.TypeResult, Payload: []byte(`{}`)}
	_, err := tasksubmit.UnmarshalSubmitRequest(frame)
	if err == nil {
		t.Fatal("expected error for wrong frame type")
	}
}

func TestUnmarshalTaskStatusUpdateWrongType(t *testing.T) {
	frame := &tasksubmit.Frame{Type: tasksubmit.TypeSubmit, Payload: []byte(`{}`)}
	_, err := tasksubmit.UnmarshalTaskStatusUpdate(frame)
	if err == nil {
		t.Fatal("expected error for wrong frame type")
	}
}

func TestUnmarshalTaskResultMessageWrongType(t *testing.T) {
	frame := &tasksubmit.Frame{Type: tasksubmit.TypeSubmit, Payload: []byte(`{}`)}
	_, err := tasksubmit.UnmarshalTaskResultMessage(frame)
	if err == nil {
		t.Fatal("expected error for wrong frame type")
	}
}

func TestMarshalUnmarshalSubmitRequestRoundTrip(t *testing.T) {
	req := &tasksubmit.SubmitRequest{
		TaskID:          "abc-123",
		TaskDescription: "compute something",
		FromAddr:        "0:0000.0000.0001",
		ToAddr:          "0:0000.0000.0002",
	}
	frame, err := tasksubmit.MarshalSubmitRequest(req)
	if err != nil {
		t.Fatalf("MarshalSubmitRequest: %v", err)
	}
	got, err := tasksubmit.UnmarshalSubmitRequest(frame)
	if err != nil {
		t.Fatalf("UnmarshalSubmitRequest: %v", err)
	}
	if got.TaskID != req.TaskID || got.TaskDescription != req.TaskDescription {
		t.Fatal("round-trip mismatch")
	}
}

func TestMarshalUnmarshalTaskStatusUpdateRoundTrip(t *testing.T) {
	upd := &tasksubmit.TaskStatusUpdate{
		TaskID:        "abc-123",
		Status:        tasksubmit.TaskStatusAccepted,
		Justification: "I can do it",
	}
	frame, err := tasksubmit.MarshalTaskStatusUpdate(upd)
	if err != nil {
		t.Fatalf("MarshalTaskStatusUpdate: %v", err)
	}
	got, err := tasksubmit.UnmarshalTaskStatusUpdate(frame)
	if err != nil {
		t.Fatalf("UnmarshalTaskStatusUpdate: %v", err)
	}
	if got.TaskID != upd.TaskID || got.Status != upd.Status {
		t.Fatal("round-trip mismatch")
	}
}

func TestMarshalUnmarshalTaskResultMessageRoundTrip(t *testing.T) {
	msg := &tasksubmit.TaskResultMessage{
		TaskID:      "abc-123",
		ResultType:  "text",
		ResultText:  "done",
		CompletedAt: "2024-01-01T00:00:00Z",
		TimeCpuMs:   60000,
	}
	frame, err := tasksubmit.MarshalTaskResultMessage(msg)
	if err != nil {
		t.Fatalf("MarshalTaskResultMessage: %v", err)
	}
	got, err := tasksubmit.UnmarshalTaskResultMessage(frame)
	if err != nil {
		t.Fatalf("UnmarshalTaskResultMessage: %v", err)
	}
	if got.TaskID != msg.TaskID || got.TimeCpuMs != msg.TimeCpuMs {
		t.Fatal("round-trip mismatch")
	}
}

func TestUnmarshalTaskFileExtraFields(t *testing.T) {
	// JSON with extra fields should not fail
	data := []byte(`{"task_id":"1","status":"NEW","extra_field":"ignored","another":42}`)
	tf, err := tasksubmit.UnmarshalTaskFile(data)
	if err != nil {
		t.Fatalf("UnmarshalTaskFile with extra fields: %v", err)
	}
	if tf.TaskID != "1" {
		t.Fatal("task_id mismatch")
	}
}

func TestPoloScoreBreakdownJSON(t *testing.T) {
	tf := &tasksubmit.TaskFile{TimeCpuMs: 60000}
	b := tf.PoloScoreRewardDetailed()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal breakdown: %v", err)
	}
	var got tasksubmit.PoloScoreBreakdown
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal breakdown: %v", err)
	}
	if got.FinalReward != b.FinalReward {
		t.Fatalf("breakdown round-trip: %d != %d", got.FinalReward, b.FinalReward)
	}
}
