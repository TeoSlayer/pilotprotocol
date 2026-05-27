// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// stubAppSocket creates a Unix socket at the install root's
// <appID>/app.sock and reads incoming length-prefixed JSON IPC
// frames from one client. It writes back stubReply (already
// length-prefixed and framed) as the response.
//
// The IPC framing matches pilot-protocol/app-store/pkg/ipc: each frame
// is [uint32 BE length][JSON body]. The client (driver-style ipc.Call)
// writes a request frame {"id":N,"method":"<m>","args":<v>} and reads
// back a reply {"id":N,"result":<v>} OR {"id":N,"error":"..."}.
func stubAppSocket(t *testing.T, root, appID string, reply []byte) (sockPath string, wait func()) {
	t.Helper()
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sockPath = filepath.Join(appDir, "app.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, err := ipc.ReadFrame(conn)
		if err != nil {
			return
		}
		resp := &ipc.Envelope{
			Type:    ipc.EnvReply,
			ReqID:   req.ReqID,
			Payload: json.RawMessage(reply),
		}
		_ = ipc.WriteFrame(conn, resp)
	}()

	return sockPath, func() { wg.Wait() }
}

func TestCmdAppStoreCallHappyPath(t *testing.T) {
	// macOS limits unix socket paths to ~104 chars including the cwd.
	// t.TempDir() returns deeply nested paths under /var/folders, so we
	// fall back to a short /tmp path here. Cleaned up via t.Cleanup.
	root, err := os.MkdirTemp("/tmp", "pilotctl-call-")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.call"
	// Drop a manifest so exposedMethods has something to read if needed.
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"),
		minimalManifestJSON(appID, []string{"echo"}), 0o600); err != nil {
		t.Fatal(err)
	}

	replyJSON := []byte(`{"echo":"hello"}`)
	_, wait := stubAppSocket(t, root, appID, replyJSON)
	defer wait()

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() {
		cmdAppStoreCall([]string{appID, "echo", `{"in":"hello"}`})
	})
	// The raw result JSON is what gets written when jsonOutput=true.
	if want := "echo"; !contains(out, want) {
		t.Errorf("expected %q in output: %q", want, out)
	}
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
