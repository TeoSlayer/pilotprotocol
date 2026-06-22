// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
	"time"
)

// TestParseFlagsBasic exercises the flag/positional split in parseFlags
// — the function every subcommand uses to interpret its argv.
func TestParseFlagsBasic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		args     []string
		wantFlag map[string]string
		wantPos  []string
	}{
		{
			name:     "empty",
			args:     []string{},
			wantFlag: map[string]string{},
			wantPos:  nil,
		},
		{
			name: "double-dash key=value",
			args: []string{"--data=hello", "--count=3"},
			wantFlag: map[string]string{
				"data":  "hello",
				"count": "3",
			},
			wantPos: nil,
		},
		{
			name: "double-dash with separate value",
			args: []string{"--data", "hello"},
			wantFlag: map[string]string{
				"data": "hello",
			},
			wantPos: nil,
		},
		{
			name: "double-dash bare bool",
			args: []string{"--reuse-conn"},
			wantFlag: map[string]string{
				"reuse-conn": "true",
			},
			wantPos: nil,
		},
		{
			name: "single-dash long flag accepted",
			args: []string{"-email", "x@y.com"},
			wantFlag: map[string]string{
				"email": "x@y.com",
			},
			wantPos: nil,
		},
		{
			name: "positional after flag",
			args: []string{"--type", "json", "my-peer"},
			wantFlag: map[string]string{
				"type": "json",
			},
			wantPos: []string{"my-peer"},
		},
		{
			name:     "negative number is positional, not a flag",
			args:     []string{"-1", "x"},
			wantFlag: map[string]string{},
			wantPos:  []string{"-1", "x"},
		},
		{
			name:     "decimal positional",
			args:     []string{"-3.14"},
			wantFlag: map[string]string{},
			wantPos:  []string{"-3.14"},
		},
		{
			name: "trailing bool flag (no value follows)",
			args: []string{"--data", "msg", "--trace"},
			wantFlag: map[string]string{
				"data":  "msg",
				"trace": "true",
			},
			wantPos: nil,
		},
		{
			name: "negative-number value is consumed by preceding flag",
			args: []string{"--count", "-1"},
			wantFlag: map[string]string{
				// "-1" is a value, not a flag, so --count consumes it.
				"count": "-1",
			},
			wantPos: nil,
		},
		{
			name: "decimal-negative value is consumed",
			args: []string{"--offset", "-3.14"},
			wantFlag: map[string]string{
				"offset": "-3.14",
			},
			wantPos: nil,
		},
		{
			name: "bare-dash value (stdin) is consumed",
			args: []string{"--file", "-"},
			wantFlag: map[string]string{
				"file": "-",
			},
			wantPos: nil,
		},
		{
			name: "dash-digit value is consumed",
			args: []string{"--rate", "-3x"},
			wantFlag: map[string]string{
				"rate": "-3x",
			},
			wantPos: nil,
		},
		{
			name: "next long flag is not consumed as a value",
			args: []string{"--data", "--trace"},
			wantFlag: map[string]string{
				"data":  "true",
				"trace": "true",
			},
			wantPos: nil,
		},
		{
			name: "next single-dash flag is not consumed as a value",
			args: []string{"--data", "-email", "x@y.com"},
			wantFlag: map[string]string{
				"data":  "true",
				"email": "x@y.com",
			},
			wantPos: nil,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotFlag, gotPos := parseFlags(tc.args)
			if len(gotFlag) != len(tc.wantFlag) {
				t.Fatalf("flag count = %d, want %d (got=%v)", len(gotFlag), len(tc.wantFlag), gotFlag)
			}
			for k, v := range tc.wantFlag {
				if gotFlag[k] != v {
					t.Errorf("flag[%q] = %q, want %q", k, gotFlag[k], v)
				}
			}
			if len(gotPos) != len(tc.wantPos) {
				t.Fatalf("pos = %v, want %v", gotPos, tc.wantPos)
			}
			for i, p := range tc.wantPos {
				if gotPos[i] != p {
					t.Errorf("pos[%d] = %q, want %q", i, gotPos[i], p)
				}
			}
		})
	}
}

func TestIsNumericFlag(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"1", true},
		{"12345", true},
		{"3.14", true},
		{".5", true},
		{"abc", false},
		{"1a", false},
		{"1.2.3", true}, // multiple dots ok per implementation (digits + dots only)
		{"-1", false},   // sign not allowed in helper
	}
	for _, tc := range cases {
		if got := isNumericFlag(tc.in); got != tc.want {
			t.Errorf("isNumericFlag(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFlagDurationHappy(t *testing.T) {
	t.Parallel()
	flags := map[string]string{
		"timeout":  "5s",
		"deadline": "2m30s",
		"secs":     "1.5",
	}
	if got := flagDuration(flags, "timeout", time.Hour); got != 5*time.Second {
		t.Errorf("timeout = %s, want 5s", got)
	}
	if got := flagDuration(flags, "deadline", 0); got != 2*time.Minute+30*time.Second {
		t.Errorf("deadline = %s", got)
	}
	if got := flagDuration(flags, "secs", 0); got != 1500*time.Millisecond {
		t.Errorf("secs = %s, want 1.5s", got)
	}
	if got := flagDuration(flags, "missing", 99*time.Second); got != 99*time.Second {
		t.Errorf("default fallback = %s", got)
	}
}

func TestFlagIntHappy(t *testing.T) {
	t.Parallel()
	flags := map[string]string{"count": "42"}
	if got := flagInt(flags, "count", -1); got != 42 {
		t.Errorf("count = %d", got)
	}
	if got := flagInt(flags, "absent", 7); got != 7 {
		t.Errorf("default = %d", got)
	}
}

func TestFlagString(t *testing.T) {
	t.Parallel()
	flags := map[string]string{"data": "hello"}
	if got := flagString(flags, "data", "def"); got != "hello" {
		t.Errorf("data = %q", got)
	}
	if got := flagString(flags, "absent", "def"); got != "def" {
		t.Errorf("absent = %q", got)
	}
}

func TestFlagBool(t *testing.T) {
	t.Parallel()
	cases := []struct {
		flags map[string]string
		key   string
		want  bool
	}{
		{map[string]string{"v": "true"}, "v", true},
		{map[string]string{"v": "1"}, "v", true},
		{map[string]string{"v": ""}, "v", true},
		{map[string]string{"v": "false"}, "v", false},
		{map[string]string{"v": "no"}, "v", false},
		{map[string]string{}, "v", false},
	}
	for _, tc := range cases {
		if got := flagBool(tc.flags, tc.key); got != tc.want {
			t.Errorf("flagBool(%v, %q) = %v, want %v", tc.flags, tc.key, got, tc.want)
		}
	}
}

func TestFmtDuration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{499 * time.Millisecond, "0s"}, // rounds down to 0s
		{500 * time.Millisecond, "1s"}, // rounds half-up to 1s
		{3 * time.Second, "3s"},
		{59 * time.Second, "59s"},
		{60 * time.Second, "1m"},
		{2*time.Minute + 5*time.Second, "2m5s"},
		{time.Hour, "1h"},
		{time.Hour + 4*time.Minute, "1h4m"},
		{2*24*time.Hour + 3*time.Hour, "2d3h"},
		{2 * 24 * time.Hour, "2d"},
	}
	for _, tc := range cases {
		if got := fmtDuration(tc.in); got != tc.want {
			t.Errorf("fmtDuration(%s) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{3 * 1024 * 1024, "3.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tc := range cases {
		if got := formatBytes(tc.in); got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasHelpFlag(t *testing.T) {
	t.Parallel()
	if !hasHelpFlag([]string{"-h"}) {
		t.Error("-h should be detected")
	}
	if !hasHelpFlag([]string{"--data", "x", "--help"}) {
		t.Error("--help should be detected at any position")
	}
	if hasHelpFlag([]string{"--data", "value"}) {
		t.Error("no help flag should be false")
	}
	if hasHelpFlag(nil) {
		t.Error("nil args should be false")
	}
}

func TestClassifyDaemonError(t *testing.T) {
	t.Parallel()
	if classifyDaemonError(nil) != "" {
		t.Error("nil error should produce empty hint")
	}
	mk := func(s string) error { return &simpleErr{s} }

	hint := classifyDaemonError(mk("pending queue full"))
	if !strings.Contains(hint, "tunnel handshake in progress") {
		t.Errorf("missing handshake hint: %q", hint)
	}

	hint = classifyDaemonError(mk("rpc: key exchange pending for peer X"))
	if !strings.Contains(hint, "tunnel handshake in progress") {
		t.Errorf("missing handshake hint via key exchange: %q", hint)
	}

	hint = classifyDaemonError(mk("dial timeout"))
	if !strings.Contains(hint, "no reply from peer") {
		t.Errorf("missing dial-timeout hint: %q", hint)
	}

	if got := classifyDaemonError(mk("some other failure mode")); got != "" {
		t.Errorf("unknown error should not match: %q", got)
	}
}

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
