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
// If the data is not valid JSON, it is treated as a plain-text message body
// and the defaultCommand is used as the command name. This allows callers to
// use `pilotctl send-message <hostname> --data "plain text"` without wrapping
// the message in JSON.
func (m *InboxMessage) ParseRequest(defaultCommand string) (*CommandRequest, error) {
	if m.Data == "" {
		return nil, fmt.Errorf("message data is empty")
	}

	// Try JSON first (legacy format: {"command":"...", "body":"..."})
	var req CommandRequest
	if err := json.Unmarshal([]byte(m.Data), &req); err == nil && req.Command != "" {
		return &req, nil
	}

	// Plain text — use as body with the default command.
	if defaultCommand == "" {
		return nil, fmt.Errorf("message is plain text but no default command configured")
	}

	// Try to unwrap JSON-encoded string (e.g. "\"hello\"")
	var unwrapped string
	if json.Unmarshal([]byte(m.Data), &unwrapped) == nil {
		return &CommandRequest{Command: defaultCommand, Body: unwrapped}, nil
	}

	return &CommandRequest{Command: defaultCommand, Body: m.Data}, nil
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
