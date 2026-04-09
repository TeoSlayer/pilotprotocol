package responder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// InboxMessage represents a message stored on disk by the pilot daemon
// at ~/.pilot/inbox/<TYPE>-<TIMESTAMP>.json.
type InboxMessage struct {
	Type       string `json:"type"`
	From       string `json:"from"`
	Data       string `json:"data"`
	Bytes      int    `json:"bytes"`
	ReceivedAt string `json:"received_at"`

	filePath string // absolute path; used for deletion after processing
}

// CommandRequest is the JSON payload expected in InboxMessage.Data.
// Senders must format their message as: {"command":"<name>","body":"<args>"}
type CommandRequest struct {
	Command string `json:"command"`
	Body    string `json:"body"`
}

// ParseRequest unmarshals the Data field into a CommandRequest.
func (m *InboxMessage) ParseRequest() (*CommandRequest, error) {
	if m.Data == "" {
		return nil, fmt.Errorf("message data is empty")
	}
	var req CommandRequest
	if err := json.Unmarshal([]byte(m.Data), &req); err != nil {
		return nil, fmt.Errorf("message data is not valid JSON (expected {\"command\":\"...\",\"body\":\"...\"}): %w", err)
	}
	if req.Command == "" {
		return nil, fmt.Errorf("message is missing required 'command' field")
	}
	return &req, nil
}

// Delete removes the inbox message file from disk.
func (m *InboxMessage) Delete() error {
	if m.filePath == "" {
		return nil
	}
	return os.Remove(m.filePath)
}

// ReadInbox reads all JSON message files from ~/.pilot/inbox/.
// Files that cannot be read or parsed are silently skipped.
// Returns nil, nil when the inbox directory does not exist yet.
func ReadInbox() ([]*InboxMessage, error) {
	dir, err := inboxDir()
	if err != nil {
		return nil, err
	}
	return ReadInboxFrom(dir)
}

// ReadInboxFrom reads all JSON message files from the given directory.
// Files that cannot be read or parsed are silently skipped.
// Returns nil, nil when the directory does not exist.
func ReadInboxFrom(dir string) ([]*InboxMessage, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read inbox: %w", err)
	}

	var msgs []*InboxMessage
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var msg InboxMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		msg.filePath = path
		msgs = append(msgs, &msg)
	}
	return msgs, nil
}

// inboxDir returns the path to the pilot inbox directory.
func inboxDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".pilot", "inbox"), nil
}
