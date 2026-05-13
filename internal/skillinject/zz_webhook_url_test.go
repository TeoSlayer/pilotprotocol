// SPDX-License-Identifier: AGPL-3.0-or-later

package skillinject

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPickWebhookURL_FirstInstalled walks tools in manifest order and
// returns the first installed tool's URL. Confirms the precedence
// contract: openclaw beats hermes if both are installed and both
// declare a URL, because openclaw comes first in the manifest.
func TestPickWebhookURL_FirstInstalled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Make BOTH ~/.openclaw and ~/.hermes exist
	if err := os.MkdirAll(filepath.Join(dir, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".hermes"), 0o700); err != nil {
		t.Fatal(err)
	}
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
		{Name: "hermes", RootDir: "~/.hermes", WebhookURL: "http://127.0.0.1:8644/pilot-events"},
	}
	url, name := pickWebhookURL(tools, dir)
	if name != "openclaw" {
		t.Fatalf("expected openclaw to win precedence, got %q", name)
	}
	if url != "http://127.0.0.1:18789/pilot-webhook" {
		t.Fatalf("url=%q", url)
	}
}

// TestPickWebhookURL_SkipsUninstalledTools confirms an asking tool
// whose rootDir doesn't exist is skipped (no false positive).
func TestPickWebhookURL_SkipsUninstalledTools(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Only hermes is installed; openclaw asks but isn't present.
	if err := os.MkdirAll(filepath.Join(dir, ".hermes"), 0o700); err != nil {
		t.Fatal(err)
	}
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
		{Name: "hermes", RootDir: "~/.hermes", WebhookURL: "http://127.0.0.1:8644/pilot-events"},
	}
	url, name := pickWebhookURL(tools, dir)
	if name != "hermes" {
		t.Fatalf("expected hermes (only one installed), got %q", name)
	}
	if url != "http://127.0.0.1:8644/pilot-events" {
		t.Fatalf("url=%q", url)
	}
}

// TestPickWebhookURL_NoTools returns empty when no tool is installed
// or no tool declares a URL.
func TestPickWebhookURL_NoTools(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
	}
	// Nothing installed in dir → pickWebhookURL returns empty.
	url, name := pickWebhookURL(tools, dir)
	if url != "" || name != "" {
		t.Fatalf("expected empty when no tool installed, got name=%q url=%q", name, url)
	}
}

// TestReconcileWebhookURL_WritesFileWhenMissing covers the cold-start
// case: ~/.pilot/webhook_url doesn't exist; we should create it with
// the picked URL.
func TestReconcileWebhookURL_WritesFileWhenMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
	}
	o := reconcileWebhookURL(dir, tools)
	if o.Action != ActionCreate {
		t.Fatalf("expected Create, got %v (err=%q)", o.Action, o.Err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".pilot", "webhook_url"))
	if err != nil {
		t.Fatalf("read-back: %v", err)
	}
	if string(got) != "http://127.0.0.1:18789/pilot-webhook" {
		t.Fatalf("on-disk url=%q", got)
	}
}

// TestReconcileWebhookURL_IdempotentWhenCorrect runs reconcile twice;
// the second call should be a Noop.
func TestReconcileWebhookURL_IdempotentWhenCorrect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
	}
	_ = reconcileWebhookURL(dir, tools)
	o := reconcileWebhookURL(dir, tools)
	if o.Action != ActionNoop {
		t.Fatalf("second tick should be Noop, got %v", o.Action)
	}
}

// TestReconcileWebhookURL_LeavesFileWhenNoToolWants ensures we don't
// blank out an operator-set URL when no installed tool asks for one
// — the daemon would lose its webhook config otherwise.
func TestReconcileWebhookURL_LeavesFileWhenNoToolWants(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Pre-populate with an operator URL.
	if err := os.MkdirAll(filepath.Join(dir, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	manual := filepath.Join(dir, ".pilot", "webhook_url")
	if err := os.WriteFile(manual, []byte("https://my-custom-endpoint.example.com/hook"), 0o600); err != nil {
		t.Fatal(err)
	}
	// No installed tool asks for a URL.
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
	}
	o := reconcileWebhookURL(dir, tools)
	if o.Action != ActionNoop {
		t.Fatalf("expected Noop when no tool asks, got %v", o.Action)
	}
	got, _ := os.ReadFile(manual)
	if string(got) != "https://my-custom-endpoint.example.com/hook" {
		t.Fatalf("operator-set URL was blanked: %q", got)
	}
}

// TestReconcileWebhookURL_RewritesOnDrift confirms that when the file
// has an old URL and the picked URL differs, we update the file.
func TestReconcileWebhookURL_RewritesOnDrift(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".openclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".pilot", "webhook_url")
	if err := os.WriteFile(path, []byte("http://127.0.0.1:18789/old-path"), 0o600); err != nil {
		t.Fatal(err)
	}
	tools := []ManifestTool{
		{Name: "openclaw", RootDir: "~/.openclaw", WebhookURL: "http://127.0.0.1:18789/pilot-webhook"},
	}
	o := reconcileWebhookURL(dir, tools)
	if o.Action != ActionRewrite {
		t.Fatalf("expected Rewrite on drift, got %v (err=%q)", o.Action, o.Err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "http://127.0.0.1:18789/pilot-webhook" {
		t.Fatalf("url not updated: %q", got)
	}
}
