// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// captureStdout runs fn while redirecting os.Stdout to a pipe, returns
// what was written. Not safe for parallel tests — the swap is global.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		mu.Lock()
		_, _ = io.Copy(&buf, r)
		mu.Unlock()
	}()

	fn()
	_ = w.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return buf.String()
}

// captureStderr is the stderr twin of captureStdout.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		mu.Lock()
		_, _ = io.Copy(&buf, r)
		mu.Unlock()
	}()
	fn()
	_ = w.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	return buf.String()
}

func TestCmdInitWritesConfig(t *testing.T) {
	tmp := withTempHomeFull(t)
	// jsonOutput off — output() will emit pretty JSON for maps.
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() {
		cmdInit([]string{
			"--registry", "r.example:9000",
			"--beacon", "b.example:9001",
			"--hostname", "test-host",
		})
	})
	if !strings.Contains(out, "r.example:9000") {
		t.Errorf("output missing registry: %s", out)
	}
	if !strings.Contains(out, "test-host") {
		t.Errorf("output missing hostname: %s", out)
	}

	// File should be on disk now.
	body, err := os.ReadFile(filepath.Join(tmp, ".pilot", defaultConfigFile))
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("config not JSON: %v", err)
	}
	if cfg["registry"] != "r.example:9000" {
		t.Errorf("registry not persisted: %v", cfg)
	}
	if cfg["hostname"] != "test-host" {
		t.Errorf("hostname not persisted: %v", cfg)
	}
}

func TestCmdInitJSONEnvelope(t *testing.T) {
	withTempHomeFull(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() {
		cmdInit([]string{"--registry", "r.x:9000"})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json envelope: %v\n%s", err, out)
	}
	if env["status"] != "ok" {
		t.Errorf("status = %v", env["status"])
	}
	data, ok := env["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("data not a map: %v", env)
	}
	if data["registry"] != "r.x:9000" {
		t.Errorf("registry data = %v", data)
	}
}

func TestCmdConfigShow(t *testing.T) {
	withTempHomeFull(t)
	// Pre-populate config.
	if err := saveConfig(map[string]interface{}{"registry": "saved:9000"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() {
		cmdConfig([]string{})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("envelope: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["registry"] != "saved:9000" {
		t.Errorf("registry not surfaced: %v", data)
	}
	if _, ok := data["config_path"]; !ok {
		t.Errorf("expected config_path in output: %v", data)
	}
}

func TestCmdConfigSet(t *testing.T) {
	tmp := withTempHomeFull(t)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() {
		cmdConfig([]string{"--set", "hostname=newhost"})
	})
	if !strings.Contains(out, "newhost") {
		t.Errorf("set response missing value: %s", out)
	}
	// Confirm written.
	cfg := loadConfig()
	if cfg["hostname"] != "newhost" {
		t.Errorf("not persisted: %v", cfg)
		_ = tmp
	}
}

func TestCmdContextEmitsJSON(t *testing.T) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, cmdContext)
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("envelope: %v", err)
	}
	data := env["data"].(map[string]interface{})
	if data["version"] == nil {
		t.Errorf("version missing: %v", data)
	}
	if data["commands"] == nil {
		t.Errorf("commands missing")
	}
	if data["extras"] == nil {
		t.Errorf("extras missing")
	}
	cmds := data["commands"].(map[string]interface{})
	// Spot-check a few documented commands.
	for _, c := range []string{"init", "config", "daemon start", "send-message", "ping", "handshake", "info"} {
		if _, ok := cmds[c]; !ok {
			t.Errorf("commands[%q] missing", c)
		}
	}
}

func TestCmdContextPrettyText(t *testing.T) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, cmdContext)
	// Pretty mode prints an indented JSON map; both modes should mention
	// some core commands.
	if !strings.Contains(out, "send-message") {
		snippet := out
		if len(snippet) > 500 {
			snippet = snippet[:500]
		}
		t.Errorf("expected send-message in text mode: %s", snippet)
	}
}

func TestCmdExtrasHelp(t *testing.T) {
	out := captureStdout(t, cmdExtrasHelp)
	for _, frag := range []string{"extras", "network delete", "policy", "managed", "audit"} {
		if !strings.Contains(out, frag) {
			t.Errorf("extras help missing %q\n--- output ---\n%s", frag, out)
		}
	}
}

// TestRedactPeerEndpointsDeepNesting hammers the recursive walker with
// a deeper structure than the existing test — slices of slices of
// maps — to lock in that recursion never panics or misses a layer.
func TestRedactPeerEndpointsDeepNesting(t *testing.T) {
	t.Parallel()
	root := map[string]interface{}{
		"keep_me": "x",
		"l1": []interface{}{
			map[string]interface{}{
				"endpoint": "1.2.3.4:5",
				"l2": []interface{}{
					[]interface{}{
						map[string]interface{}{
							"real_addr": "drop",
							"id":        99,
						},
					},
				},
			},
		},
	}
	redactPeerEndpoints(root)
	if root["keep_me"] != "x" {
		t.Errorf("top-level scalar removed")
	}
	l1 := root["l1"].([]interface{})[0].(map[string]interface{})
	if _, ok := l1["endpoint"]; ok {
		t.Errorf("l1.endpoint not redacted")
	}
	l2 := l1["l2"].([]interface{})[0].([]interface{})[0].(map[string]interface{})
	if _, ok := l2["real_addr"]; ok {
		t.Errorf("l2.real_addr not redacted")
	}
	if l2["id"] != 99 {
		t.Errorf("l2.id preserved? got %v", l2["id"])
	}
}
