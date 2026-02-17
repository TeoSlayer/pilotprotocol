package tasksubmit

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Status codes for task submission responses.
const (
	StatusAccepted = 200
	StatusRejected = 400
)

// Frame types for task submission on port 1003.
const (
	TypeSubmit uint32 = 1 // Task submission request
	TypeResult uint32 = 2 // Task result response
)

// SubmitRequest represents a task submission request.
type SubmitRequest struct {
	TaskDescription string `json:"task_description"`
}

// SubmitResponse represents the response to a task submission.
type SubmitResponse struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// TaskResult represents the result of a completed task.
type TaskResult struct {
	TaskDescription string      `json:"task_description"`
	Status          string      `json:"status"` // "success" or "error"
	Result          interface{} `json:"result"` // can be string, object, etc.
	Error           string      `json:"error,omitempty"`
	Timestamp       string      `json:"timestamp"`
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
