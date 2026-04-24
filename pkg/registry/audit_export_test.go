// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Iter-115 coverage for registry/audit_export.go — newAuditExporter, Export,
// Close, run, send, formatSplunkHEC, formatCEF, Stats (all 0% baseline).
// pkg/registry overall is at 4.2%; audit_export.go is self-contained and
// testable with httptest + pure format tests, so it's a high-leverage target.

// --- Export + Close + Stats (no HTTP): exercises the buffered-channel path ---

func TestNewAuditExporterSpawnsRunAndCloseStopsIt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ae := newAuditExporter(&BlueprintAuditExport{Format: "json", Endpoint: srv.URL})
	if ae == nil {
		t.Fatal("newAuditExporter returned nil")
	}
	// Close should drain and stop the goroutine within 5s.
	start := time.Now()
	ae.Close()
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Close blocked too long: %v", elapsed)
	}
}

func TestAuditExporterNilExportIsNoop(t *testing.T) {
	var ae *AuditExporter
	ae.Export(&AuditEntry{Action: "x"}) // must NOT panic
	ae.Close()                          // must NOT panic
	exported, dropped := ae.Stats()
	if exported != 0 || dropped != 0 {
		t.Fatalf("nil Stats = (%d, %d), want (0, 0)", exported, dropped)
	}
}

func TestAuditExporterExportIncrementsExportedOnSuccess(t *testing.T) {
	var hits atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ae := newAuditExporter(&BlueprintAuditExport{Format: "json", Endpoint: srv.URL})
	defer ae.Close()

	ae.Export(&AuditEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "create_network",
		NetworkID: 42,
		NodeID:    100,
		Details:   "ok",
	})

	// Poll for hits + exported counter.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatalf("server hits = %d, want 1", hits.Load())
	}
	// Also poll for exported counter (run goroutine may not have updated yet).
	for time.Now().Before(deadline) {
		if exported, _ := ae.Stats(); exported == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	exported, _ := ae.Stats()
	t.Fatalf("exported = %d, want 1 within 3s", exported)
}

func TestAuditExporterExportBufferFullIncrementsDropped(t *testing.T) {
	// Construct an AuditExporter WITHOUT spawning the run goroutine — this lets
	// ch fill up on the first Exports and forces the `default` drop branch in
	// Export's second select to fire, incrementing `dropped`. Using a real
	// newAuditExporter + a blocking server would deadlock the race-suite
	// teardown because run() hangs inside http.Client.Do on shutdown.
	ae := &AuditExporter{
		config: &BlueprintAuditExport{Format: "json", Endpoint: ""},
		ch:     make(chan *AuditEntry, 4), // tiny buffer
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	// Drop path: fill buffer, then every subsequent Export should increment dropped.
	for i := 0; i < 20; i++ {
		ae.Export(&AuditEntry{Action: "flood", NodeID: uint32(i)})
	}
	_, dropped := ae.Stats()
	if dropped == 0 {
		t.Fatalf("dropped = 0 after 20 Exports into 4-buffer, want > 0")
	}
	// Minimum expected drops: 20 sends - 4 buffer slots = 16.
	if dropped < 16 {
		t.Fatalf("dropped = %d, want >= 16 (20 sent - 4 buffered)", dropped)
	}
}

func TestAuditExporterExportAfterCloseIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ae := newAuditExporter(&BlueprintAuditExport{Format: "json", Endpoint: srv.URL})
	ae.Close()

	// Post-Close Export must NOT panic (select on closed channel would otherwise).
	// It also must NOT increment dropped — the EARLY return at the first `select`
	// (ae.closed has been closed → case fires) handles it before the second select.
	ae.Export(&AuditEntry{Action: "post-close"})
	_, dropped := ae.Stats()
	if dropped != 0 {
		t.Fatalf("dropped after Close = %d, want 0 (early return path)", dropped)
	}
}

func TestAuditExporterCloseIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ae := newAuditExporter(&BlueprintAuditExport{Format: "json", Endpoint: srv.URL})
	ae.Close()
	ae.Close() // second Close must be a no-op via closeOnce
}

// --- send(): 4xx client error does NOT retry; 5xx server error retries 3× ---

func TestAuditExporterSendClientErrorDoesNotRetry(t *testing.T) {
	var attempts atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest) // 400
	}))
	defer srv.Close()

	ae := newAuditExporter(&BlueprintAuditExport{Format: "json", Endpoint: srv.URL})
	defer ae.Close()

	ae.Export(&AuditEntry{Action: "client-err"})

	// Poll: attempt count should stay at 1 (no retry on 4xx).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Give it a beat to confirm no retry.
	time.Sleep(200 * time.Millisecond)
	if attempts.Load() != 1 {
		t.Fatalf("attempts on 4xx = %d, want 1 (no retry)", attempts.Load())
	}
	exported, _ := ae.Stats()
	if exported != 0 {
		t.Fatalf("exported on 4xx = %d, want 0", exported)
	}
}

// --- formatSplunkHEC: hits all branches of format body ---

func TestFormatSplunkHECEmitsExpectedFields(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{
		Format: "splunk_hec", Source: "", Index: "pilot-audit",
	}}
	ts := time.Now().UTC().Truncate(time.Second)
	body, err := ae.formatSplunkHEC(&AuditEntry{
		Timestamp: ts.Format(time.RFC3339),
		Action:    "register",
		NetworkID: 7,
		NodeID:    42,
		Details:   "ok",
	})
	if err != nil {
		t.Fatalf("formatSplunkHEC: %v", err)
	}
	var hec SplunkHECEvent
	if err := json.Unmarshal(body, &hec); err != nil {
		t.Fatalf("unmarshal HEC: %v (body=%s)", err, body)
	}
	if hec.Time != ts.Unix() {
		t.Fatalf("hec.Time = %d, want %d", hec.Time, ts.Unix())
	}
	if hec.Source != "pilot-registry" {
		t.Fatalf("default Source = %q, want pilot-registry", hec.Source)
	}
	if hec.SourceType != "pilot:audit" {
		t.Fatalf("SourceType = %q, want pilot:audit", hec.SourceType)
	}
	if hec.Index != "pilot-audit" {
		t.Fatalf("Index = %q, want pilot-audit", hec.Index)
	}
	if got := hec.Event["action"]; got != "register" {
		t.Fatalf("event.action = %v, want register", got)
	}
	if got, _ := hec.Event["network_id"].(float64); uint16(got) != 7 {
		t.Fatalf("event.network_id = %v, want 7", hec.Event["network_id"])
	}
	if got, _ := hec.Event["node_id"].(float64); uint32(got) != 42 {
		t.Fatalf("event.node_id = %v, want 42", hec.Event["node_id"])
	}
	if got := hec.Event["details"]; got != "ok" {
		t.Fatalf("event.details = %v, want ok", got)
	}
}

func TestFormatSplunkHECUsesProvidedSource(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{
		Format: "splunk_hec", Source: "custom-host",
	}}
	body, err := ae.formatSplunkHEC(&AuditEntry{Action: "a"})
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	var hec SplunkHECEvent
	if err := json.Unmarshal(body, &hec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if hec.Source != "custom-host" {
		t.Fatalf("Source = %q, want custom-host (override)", hec.Source)
	}
}

func TestFormatSplunkHECZeroTimestampFallsBackToNow(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{Format: "splunk_hec"}}
	before := time.Now().Unix()
	body, err := ae.formatSplunkHEC(&AuditEntry{Action: "a", Timestamp: ""})
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	after := time.Now().Unix()
	var hec SplunkHECEvent
	if err := json.Unmarshal(body, &hec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if hec.Time < before || hec.Time > after {
		t.Fatalf("hec.Time = %d, not in [%d, %d] (want time.Now fallback)", hec.Time, before, after)
	}
}

func TestFormatSplunkHECOmitsDetailsWhenEmpty(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{Format: "splunk_hec"}}
	body, err := ae.formatSplunkHEC(&AuditEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Action:    "a",
	})
	if err != nil {
		t.Fatalf("format: %v", err)
	}
	var hec SplunkHECEvent
	if err := json.Unmarshal(body, &hec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := hec.Event["details"]; ok {
		t.Fatalf(`event["details"] should be absent when Details="" `)
	}
}

// --- formatCEF: severity routing + extension formatting ---

func TestFormatCEFSeverityInformationalForNormalActions(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{Format: "syslog_cef"}}
	body, err := ae.formatCEF(&AuditEntry{Action: "register", NetworkID: 5, NodeID: 12})
	if err != nil {
		t.Fatalf("formatCEF: %v", err)
	}
	line := string(body)
	if !strings.HasPrefix(line, "CEF:0|Pilot|Registry|1.0|register|register|3|") {
		t.Fatalf("CEF prefix wrong, got: %s", line)
	}
	if !strings.Contains(line, "cs1=register") {
		t.Fatalf("missing cs1=register in: %s", line)
	}
	if !strings.Contains(line, "cn1=5") {
		t.Fatalf("missing cn1=5 in: %s", line)
	}
	if !strings.Contains(line, "cn2=12") {
		t.Fatalf("missing cn2=12 in: %s", line)
	}
	if strings.Contains(line, "msg=") {
		t.Fatalf("msg= should be absent when Details empty: %s", line)
	}
}

func TestFormatCEFSeverityHighForKickOrDelete(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{Format: "syslog_cef"}}
	for _, action := range []string{"kick_member", "delete_network", "member_kick"} {
		body, _ := ae.formatCEF(&AuditEntry{Action: action})
		line := string(body)
		// severity 6 (high)
		if !strings.Contains(line, "|"+action+"|"+action+"|6|") {
			t.Fatalf("action %q severity != 6, got: %s", action, line)
		}
	}
}

func TestFormatCEFSeverityMediumForPromoteDemote(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{Format: "syslog_cef"}}
	for _, action := range []string{"promote_admin", "demote_member"} {
		body, _ := ae.formatCEF(&AuditEntry{Action: action})
		line := string(body)
		if !strings.Contains(line, "|"+action+"|"+action+"|4|") {
			t.Fatalf("action %q severity != 4, got: %s", action, line)
		}
	}
}

func TestFormatCEFAppendsMsgWhenDetailsSet(t *testing.T) {
	ae := &AuditExporter{config: &BlueprintAuditExport{Format: "syslog_cef"}}
	body, _ := ae.formatCEF(&AuditEntry{Action: "register", Details: "by-op"})
	line := string(body)
	if !strings.HasSuffix(line, " msg=by-op") {
		t.Fatalf("expected trailing msg=by-op, got: %s", line)
	}
}

// --- send() path-dispatch: unknown format falls through to json.Marshal ---

func TestSendUnknownFormatUsesJSON(t *testing.T) {
	var captured atomic.Value // stores []byte
	var ct atomic.Value       // stores string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		captured.Store(append([]byte{}, buf[:n]...))
		ct.Store(r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Format="" hits the default switch branch (json.Marshal).
	ae := newAuditExporter(&BlueprintAuditExport{Format: "", Endpoint: srv.URL})
	defer ae.Close()

	ae.Export(&AuditEntry{Action: "default-fmt", NetworkID: 1, NodeID: 2})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c := captured.Load(); c != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	body, _ := captured.Load().([]byte)
	if len(body) == 0 {
		t.Fatal("server received no body")
	}
	if got, _ := ct.Load().(string); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var entry AuditEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		t.Fatalf("body not JSON: %v (body=%s)", err, body)
	}
	if entry.Action != "default-fmt" {
		t.Fatalf("entry.Action = %q, want default-fmt", entry.Action)
	}
}

// --- send() splunk_hec path injects Authorization header when Token set ---

func TestSendSplunkHECSetsAuthHeaderWhenTokenProvided(t *testing.T) {
	var authHeader atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ae := newAuditExporter(&BlueprintAuditExport{
		Format: "splunk_hec", Endpoint: srv.URL, Token: "secret-token",
	})
	defer ae.Close()

	ae.Export(&AuditEntry{Timestamp: time.Now().Format(time.RFC3339), Action: "a"})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h := authHeader.Load(); h != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _ := authHeader.Load().(string)
	if got != "Splunk secret-token" {
		t.Fatalf("Authorization = %q, want %q", got, "Splunk secret-token")
	}
}
