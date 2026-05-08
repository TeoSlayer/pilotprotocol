// SPDX-License-Identifier: AGPL-3.0-or-later

package policy

import (
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// validateAction — exercise every required-param branch
// ---------------------------------------------------------------------------

func TestValidateActionMissingParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		action Action
		want   string
	}{
		{"tag", Action{Type: ActionTag}, "tag requires 'add' or 'remove'"},
		{"evict_where", Action{Type: ActionEvictWhere}, "evict_where requires 'match'"},
		{"prune", Action{Type: ActionPrune}, "prune requires 'count'"},
		{"fill", Action{Type: ActionFill}, "fill requires 'count'"},
		{"prune_trust_no_percent", Action{Type: ActionPruneTrust, Params: map[string]interface{}{"min": 1.0}}, "prune_trust requires 'percent'"},
		{"prune_trust_no_min", Action{Type: ActionPruneTrust, Params: map[string]interface{}{"percent": 0.5}}, "prune_trust requires 'min'"},
		{"fill_trust", Action{Type: ActionFillTrust}, "fill_trust requires 'target'"},
		{"webhook", Action{Type: ActionWebhook}, "webhook requires 'event'"},
		{"log", Action{Type: ActionLog}, "log requires 'message'"},
		{"unknown", Action{Type: ActionType("nope")}, "unknown action type"},
	}
	for _, tc := range cases {
		err := validateAction("rule", 0, tc.action)
		if err == nil {
			t.Errorf("%s: expected error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q missing %q", tc.name, err, tc.want)
		}
	}
}

func TestValidateActionAccepts(t *testing.T) {
	t.Parallel()
	cases := []Action{
		{Type: ActionAllow},
		{Type: ActionDeny},
		{Type: ActionEvict},
		{Type: ActionTag, Params: map[string]interface{}{"add": "x"}},
		{Type: ActionTag, Params: map[string]interface{}{"remove": "x"}},
		{Type: ActionEvictWhere, Params: map[string]interface{}{"match": "true"}},
		{Type: ActionPrune, Params: map[string]interface{}{"count": 1.0}},
		{Type: ActionFill, Params: map[string]interface{}{"count": 1.0}},
		{Type: ActionPruneTrust, Params: map[string]interface{}{"percent": 0.5, "min": 1.0}},
		{Type: ActionFillTrust, Params: map[string]interface{}{"target": "node"}},
		{Type: ActionWebhook, Params: map[string]interface{}{"event": "alert"}},
		{Type: ActionLog, Params: map[string]interface{}{"message": "hi"}},
	}
	for _, a := range cases {
		if err := validateAction("rule", 0, a); err != nil {
			t.Errorf("%v: unexpected error %v", a.Type, err)
		}
	}
}

// ---------------------------------------------------------------------------
// env helpers: durationFn, sinceFn
// ---------------------------------------------------------------------------

func TestDurationFnValid(t *testing.T) {
	t.Parallel()
	cases := map[string]float64{
		"1s":      1,
		"1m":      60,
		"1h":      3600,
		"500ms":   0.5,
		"1h30m":   5400,
	}
	for in, want := range cases {
		got, err := durationFn(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if g := got.(float64); g != want {
			t.Errorf("%q: got %v, want %v", in, g, want)
		}
	}
}

func TestDurationFnInvalid(t *testing.T) {
	t.Parallel()
	got, err := durationFn("not a duration")
	if err == nil {
		t.Fatalf("expected parse error, got %v", got)
	}
	// On error, function returns (0.0, err) per implementation
	if g, ok := got.(float64); !ok || g != 0.0 {
		t.Errorf("on error got %v (%T), want 0.0", got, got)
	}
}

func TestSinceFnZeroOrNegativeReturnsZero(t *testing.T) {
	t.Parallel()
	for _, ts := range []float64{0, -1, -1000} {
		got, err := sinceFn(ts)
		if err != nil {
			t.Errorf("%v: %v", ts, err)
		}
		if g := got.(float64); g != 0 {
			t.Errorf("ts=%v: got %v, want 0", ts, g)
		}
	}
}

func TestSinceFnPositiveTimestampReturnsElapsed(t *testing.T) {
	t.Parallel()
	// 10 seconds ago
	ts := float64(time.Now().Add(-10 * time.Second).Unix())
	got, err := sinceFn(ts)
	if err != nil {
		t.Fatal(err)
	}
	g := got.(float64)
	if g < 9 || g > 12 {
		t.Errorf("got %v seconds, want roughly 10", g)
	}
}

// ---------------------------------------------------------------------------
// MaxPeers branches
// ---------------------------------------------------------------------------

func TestMaxPeersFromFloat64(t *testing.T) {
	t.Parallel()
	cp := &CompiledPolicy{Doc: PolicyDocument{Config: map[string]interface{}{"max_peers": float64(150)}}}
	if got := cp.MaxPeers(); got != 150 {
		t.Errorf("got %d, want 150", got)
	}
}

func TestMaxPeersFromInt(t *testing.T) {
	t.Parallel()
	cp := &CompiledPolicy{Doc: PolicyDocument{Config: map[string]interface{}{"max_peers": 42}}}
	if got := cp.MaxPeers(); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
}

func TestMaxPeersMissingReturnsZero(t *testing.T) {
	t.Parallel()
	cp := &CompiledPolicy{Doc: PolicyDocument{Config: map[string]interface{}{}}}
	if got := cp.MaxPeers(); got != 0 {
		t.Errorf("got %d, want 0 (missing key)", got)
	}
}

func TestMaxPeersNilConfigReturnsZero(t *testing.T) {
	t.Parallel()
	cp := &CompiledPolicy{Doc: PolicyDocument{Config: nil}}
	if got := cp.MaxPeers(); got != 0 {
		t.Errorf("got %d, want 0 (nil config)", got)
	}
}

func TestMaxPeersUnsupportedTypeReturnsZero(t *testing.T) {
	t.Parallel()
	// String value should not be coerced
	cp := &CompiledPolicy{Doc: PolicyDocument{Config: map[string]interface{}{"max_peers": "150"}}}
	if got := cp.MaxPeers(); got != 0 {
		t.Errorf("got %d, want 0 (unsupported type)", got)
	}
}
