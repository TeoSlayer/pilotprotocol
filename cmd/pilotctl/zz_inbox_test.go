// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCmdInboxEmpty(t *testing.T) {
	withTempHomeFull(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdInbox(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["total"] != float64(0) {
		t.Errorf("total = %v", data["total"])
	}
}

func TestCmdInboxEmptyTextMode(t *testing.T) {
	withTempHomeFull(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdInbox(nil) })
	if !strings.Contains(out, "inbox is empty") {
		t.Errorf("expected 'inbox is empty' in: %s", out)
	}
}

func TestCmdInboxWithMessages(t *testing.T) {
	tmp := withTempHomeFull(t)
	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, msg := range []map[string]any{
		{"type": "text", "from": "peer1", "data": "hello there", "bytes": float64(11), "received_at": "2026-05-27T10:00:00.123456789Z"},
		{"type": "json", "from": "peer2", "data": "{\"a\":1}", "bytes": float64(7), "received_at": "2026-05-27T10:01:00.987654321Z"},
	} {
		body, _ := json.Marshal(msg)
		// filenames are {type}-{ts}-{seq}.json
		fname := msg["type"].(string) + "-100000000" + string(rune('0'+i)) + "-0.json"
		if err := os.WriteFile(filepath.Join(inboxDir, fname), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdInbox(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["total"] != float64(2) {
		t.Errorf("total = %v, want 2", data["total"])
	}
}

func TestCmdInboxWithMessagesTextMode(t *testing.T) {
	tmp := withTempHomeFull(t)
	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	msg := map[string]any{
		"type":        "text",
		"from":        "peer-alpha",
		"data":        "hello",
		"bytes":       float64(5),
		"received_at": "2026-05-27T10:00:00.123456789Z",
	}
	body, _ := json.Marshal(msg)
	if err := os.WriteFile(filepath.Join(inboxDir, "text-1000000000-0.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdInbox([]string{"--trace"}) })
	for _, frag := range []string{"Inbox", "peer-alpha", "hello"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdReceivedEmpty(t *testing.T) {
	withTempHomeFull(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdReceived(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v", err)
	}
	data := env["data"].(map[string]interface{})
	if data["total"] != float64(0) {
		t.Errorf("total = %v", data["total"])
	}
}

func TestCmdReceivedEmptyTextMode(t *testing.T) {
	withTempHomeFull(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdReceived(nil) })
	if !strings.Contains(out, "no received files") {
		t.Errorf("expected 'no received files' in: %s", out)
	}
}

func TestCmdReceivedWithFiles(t *testing.T) {
	tmp := withTempHomeFull(t)
	recvDir := filepath.Join(tmp, ".pilot", "received")
	if err := os.MkdirAll(recvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recvDir, "a.bin"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recvDir, "b.bin"), []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdReceived(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["total"] != float64(2) {
		t.Errorf("total = %v", data["total"])
	}
}

func TestCmdReceivedWithFilesTextMode(t *testing.T) {
	tmp := withTempHomeFull(t)
	recvDir := filepath.Join(tmp, ".pilot", "received")
	if err := os.MkdirAll(recvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recvDir, "report.pdf"), []byte("PDF"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdReceived(nil) })
	for _, frag := range []string{"Received files", "report.pdf", "total"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdInboxClear(t *testing.T) {
	tmp := withTempHomeFull(t)
	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Drop a few files.
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(inboxDir, "msg-x-"+string(rune('a'+i))+".json"),
			[]byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdInbox([]string{"--clear"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["cleared"] != float64(3) {
		t.Errorf("cleared = %v", data["cleared"])
	}
	// All files gone.
	entries, _ := os.ReadDir(inboxDir)
	if len(entries) != 0 {
		t.Errorf("expected empty after clear, got %d entries", len(entries))
	}
}

func TestWaitForInboxReplyHit(t *testing.T) {
	tmp := withTempHomeFull(t)
	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a message after the cutoff.
	cutoff := time.Now().Add(-time.Second)
	msg := map[string]any{"from": "expected-agent", "data": "reply-body"}
	body, _ := json.Marshal(msg)
	if err := os.WriteFile(filepath.Join(inboxDir, "text-99-0.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := waitForInboxReply("expected-agent", cutoff, 5*time.Second)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got["data"] != "reply-body" {
		t.Errorf("data = %v", got["data"])
	}
}

func TestWaitForInboxReplyTimeout(t *testing.T) {
	tmp := withTempHomeFull(t)
	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := waitForInboxReply("nobody", time.Now(), 500*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
	if !strings.Contains(err.Error(), "nobody") {
		t.Errorf("err missing agent hint: %v", err)
	}
}

func TestWaitForInboxReplyFiltersOldFiles(t *testing.T) {
	tmp := withTempHomeFull(t)
	inboxDir := filepath.Join(tmp, ".pilot", "inbox")
	if err := os.MkdirAll(inboxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// File predates cutoff — should be ignored.
	oldMsg := map[string]any{"from": "x", "data": "old"}
	body, _ := json.Marshal(oldMsg)
	oldPath := filepath.Join(inboxDir, "text-0-0.json")
	if err := os.WriteFile(oldPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// Bump mtime to past.
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldPath, past, past); err != nil {
		t.Fatal(err)
	}

	_, err := waitForInboxReply("x", time.Now(), 300*time.Millisecond)
	if err == nil {
		t.Error("expected timeout — old file should not match")
	}
}

func TestCmdReceivedClear(t *testing.T) {
	tmp := withTempHomeFull(t)
	recvDir := filepath.Join(tmp, ".pilot", "received")
	if err := os.MkdirAll(recvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := os.WriteFile(filepath.Join(recvDir, "f"+string(rune('a'+i))), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdReceived([]string{"--clear"}) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v", err)
	}
	data := env["data"].(map[string]interface{})
	if data["cleared"] != float64(2) {
		t.Errorf("cleared = %v", data["cleared"])
	}
}
