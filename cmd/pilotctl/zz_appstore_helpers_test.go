// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

func TestBoolToReady(t *testing.T) {
	t.Parallel()
	if boolToReady(true) != "ready" {
		t.Error("true should map to 'ready'")
	}
	if boolToReady(false) != "not ready" {
		t.Error("false should map to 'not ready'")
	}
}

func TestBoolToPresent(t *testing.T) {
	t.Parallel()
	if boolToPresent(true) != "present" {
		t.Error("true should map to 'present'")
	}
	if boolToPresent(false) != "missing" {
		t.Error("false should map to 'missing'")
	}
}

func TestShortHex(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"abcd", "abcd"},
		{"0123456789abcdef", "0123456789abcdef"}, // exactly 16 → unchanged
		{"0123456789abcdef0", "01234567…cdef0"[:len("01234567")+len("…")+5]},
	}
	// First three are deterministic with the implementation; the last is
	// constructed at compile-time, so just spot-check the contract:
	// 8 prefix chars + ellipsis + 4 suffix chars for >16-char inputs.
	for _, tc := range cases[:3] {
		if got := shortHex(tc.in); got != tc.want {
			t.Errorf("shortHex(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("a", 8) + strings.Repeat("b", 50) + "deadbeef"
	got := shortHex(long)
	if !strings.HasPrefix(got, long[:8]) {
		t.Errorf("shortHex %q lost prefix: %q", long, got)
	}
	if !strings.HasSuffix(got, "beef") {
		t.Errorf("shortHex %q lost suffix: %q", long, got)
	}
	if !strings.Contains(got, "…") {
		t.Errorf("shortHex %q missing ellipsis: %q", long, got)
	}
}

func TestValidationErrSummary(t *testing.T) {
	t.Parallel()
	if got := validationErrSummary(nil); got != "(no errors)" {
		t.Errorf("nil = %q", got)
	}
	if got := validationErrSummary([]error{}); got != "(no errors)" {
		t.Errorf("empty = %q", got)
	}
	e1 := errors.New("first thing wrong")
	if got := validationErrSummary([]error{e1}); got != "first thing wrong" {
		t.Errorf("single = %q", got)
	}
	e2 := errors.New("second thing wrong")
	got := validationErrSummary([]error{e1, e2})
	if !strings.Contains(got, "first thing wrong") || !strings.Contains(got, "+1 more") {
		t.Errorf("multi = %q", got)
	}
}

func TestHumanDuration(t *testing.T) {
	t.Parallel()
	// humanDuration decomposes the duration into h/m/s components and
	// emits only the non-zero ones. The previous implementation used
	// strings.TrimSuffix(s, "0m") which over-stripped — "1h30m0s" became
	// "1h3" and "10m0s" became "1". The cases marked "fixed:" below pin
	// the corrected behavior so the bug can't quietly come back.
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{24 * time.Hour, "24h"},
		{time.Hour, "1h"},
		{time.Hour + 30*time.Minute, "1h30m"}, // fixed: was "1h3"
		{10 * time.Minute, "10m"},             // fixed: was "1"
		{2*time.Hour + 5*time.Minute + 30*time.Second, "2h5m30s"}, // fixed: was "2h5m3"
		{time.Hour, "1h"}, // fixed canonical: "1h0m0s" -> "1h"
		{45 * time.Second, "45s"},
		{time.Hour + 11*time.Minute, "1h11m"},
		{5 * time.Minute, "5m"},
		{2*time.Hour + 5*time.Minute + 1*time.Second, "2h5m1s"},
	}
	for _, tc := range cases {
		if got := humanDuration(tc.in); got != tc.want {
			t.Errorf("humanDuration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseCapsFromGrants(t *testing.T) {
	t.Parallel()
	// Non-cap grants are ignored.
	grants := []manifest.Grant{
		{Cap: "fs.read", Target: "/tmp"},
		{Cap: "key.sign"}, // no condition → skipped
		{
			Cap: "key.sign",
			Condition: &manifest.Condition{
				Kind: "rate",
			}, // wrong kind → skipped
		},
		{
			Cap:    "key.sign",
			Target: "x402-auth",
			Condition: &manifest.Condition{
				Kind: "cap",
				Params: map[string]interface{}{
					"asset": "USDC",
					"per":   "hour",
					"limit": float64(100),
				},
			},
		},
		{
			Cap:    "key.sign",
			Target: "evm-eip3009",
			Condition: &manifest.Condition{
				Kind: "cap",
				Params: map[string]interface{}{
					"asset": "ETH",
					"per":   "day",
					"limit": float64(5),
				},
			},
		},
		{
			// Bad per — skipped.
			Cap: "key.sign",
			Condition: &manifest.Condition{
				Kind: "cap",
				Params: map[string]interface{}{
					"asset": "USDC",
					"per":   "week",
					"limit": float64(1),
				},
			},
		},
		{
			// Missing asset — skipped.
			Cap: "key.sign",
			Condition: &manifest.Condition{
				Kind: "cap",
				Params: map[string]interface{}{
					"per":   "hour",
					"limit": float64(1),
				},
			},
		},
	}
	out := parseCapsFromGrants(grants)
	if len(out) != 2 {
		t.Fatalf("expected 2 caps, got %d: %+v", len(out), out)
	}
	if out[0].asset != "USDC" || out[0].limit != 100 || out[0].window != time.Hour {
		t.Errorf("first cap wrong: %+v", out[0])
	}
	if out[1].asset != "ETH" || out[1].limit != 5 || out[1].window != 24*time.Hour {
		t.Errorf("second cap wrong: %+v", out[1])
	}
	if out[0].target != "x402-auth" {
		t.Errorf("target lost: %+v", out[0])
	}
}

func TestParseCapsFromGrantsMinuteWindow(t *testing.T) {
	t.Parallel()
	grants := []manifest.Grant{
		{
			Cap: "key.sign",
			Condition: &manifest.Condition{
				Kind: "cap",
				Params: map[string]interface{}{
					"asset": "USDC",
					"per":   "min",
					"limit": float64(10),
				},
			},
		},
		{
			Cap: "key.sign",
			Condition: &manifest.Condition{
				Kind: "cap",
				Params: map[string]interface{}{
					"asset": "USDC",
					"per":   "minute",
					"limit": float64(20),
				},
			},
		},
	}
	out := parseCapsFromGrants(grants)
	if len(out) != 2 {
		t.Fatalf("got %d, want 2", len(out))
	}
	if out[0].window != time.Minute || out[1].window != time.Minute {
		t.Errorf("min/minute should both → 1m: %+v %+v", out[0], out[1])
	}
}

func TestLoadCapStateRecordsMissingFile(t *testing.T) {
	t.Parallel()
	got := loadCapStateRecords(filepath.Join(t.TempDir(), "does-not-exist.jsonl"))
	if got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

func TestLoadCapStateRecordsSkipsMalformedLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "cap-state.jsonl")
	content := `{"at":"2026-05-27T10:00:00Z","asset":"USDC","amount":5}
not-json garbage line
{"at":"2026-05-27T10:05:00Z","asset":"ETH","amount":2}

{"at":"2026-05-27T10:10:00Z","asset":"USDC","amount":7}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	recs := loadCapStateRecords(path)
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (malformed should be skipped): %+v", len(recs), recs)
	}
	if recs[0].asset != "USDC" || recs[0].amount != 5 {
		t.Errorf("first rec wrong: %+v", recs[0])
	}
	if recs[2].asset != "USDC" || recs[2].amount != 7 {
		t.Errorf("third rec wrong: %+v", recs[2])
	}
}

func TestSHA256FileHandlesMissing(t *testing.T) {
	t.Parallel()
	// Missing file returns empty string, not panic.
	if got := sha256File(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("missing file → %q, want empty", got)
	}
}

func TestSHA256FileKnownDigest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "data")
	// SHA256("abc") == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := sha256File(path)
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCopyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	body := []byte("hello world\n")
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst, 0o600); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("body mismatch: got %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Mode is masked on some systems but the 0600 bits we care about
	// should at minimum NOT contain world or group bits.
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("perm bits leaked: %o", info.Mode().Perm())
	}
}

func TestCopyFileMissingSource(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := copyFile(filepath.Join(dir, "nope"), filepath.Join(dir, "out"), 0o600)
	if err == nil {
		t.Error("expected error on missing src, got nil")
	}
}

func TestAppStoreRootEnvOverride(t *testing.T) {
	custom := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", custom)
	if got := appStoreRoot(); got != custom {
		t.Errorf("env override = %q, want %q", got, custom)
	}
}

func TestAppStoreRootHomeFallback(t *testing.T) {
	t.Setenv("PILOT_APPSTORE_ROOT", "")
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	got := appStoreRoot()
	if !strings.HasPrefix(got, tmp) {
		t.Errorf("home fallback should live under %s, got %s", tmp, got)
	}
	if !strings.HasSuffix(got, defaultAppStoreRoot) {
		t.Errorf("got %s, want suffix %s", got, defaultAppStoreRoot)
	}
}

func TestCurrentActor(t *testing.T) {
	t.Setenv("USER", "tester")
	if got := currentActor(); got != "tester" {
		t.Errorf("USER override = %q", got)
	}
	t.Setenv("USER", "")
	if got := currentActor(); got != "unknown" {
		t.Errorf("empty USER = %q, want 'unknown'", got)
	}
}

// TestExposedMethodsParsesManifest writes a minimal manifest and
// confirms exposedMethods returns a sorted copy of `exposes`.
func TestExposedMethodsParsesManifest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)

	appID := "io.test.app"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Minimal valid manifest with an Exposes list — only the Parse path
	// matters here, not Validate. Parse just decodes JSON.
	mfRaw := []byte(`{
		"id": "io.test.app",
		"app_version": "1.0.0",
		"manifest_version": 1,
		"binary": {"runtime": "go", "path": "bin", "sha256": "abc"},
		"exposes": ["zeta.method", "alpha.method", "beta.method"],
		"grants": [],
		"store": {"publisher": "ed25519:test", "signature": "sig"}
	}`)
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), mfRaw, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	got := exposedMethods(appID)
	want := []string{"alpha.method", "beta.method", "zeta.method"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, m := range want {
		if got[i] != m {
			t.Errorf("got[%d] = %q, want %q", i, got[i], m)
		}
	}
}

func TestExposedMethodsMissingManifest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	if got := exposedMethods("never.installed"); got != nil {
		t.Errorf("missing manifest should be nil, got %v", got)
	}
}

func TestExposedMethodsCorruptManifest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appDir := filepath.Join(root, "corrupt.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte("not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := exposedMethods("corrupt.app"); got != nil {
		t.Errorf("corrupt manifest should be nil, got %v", got)
	}
}
