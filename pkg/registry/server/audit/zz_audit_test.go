// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/server/events"
	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// ---------------------------------------------------------------------------
// Store: ring buffer via Append (synchronous path)
// ---------------------------------------------------------------------------

// TestStoreAppendWritesToRingBuffer verifies that Append synchronously adds
// entries to the ring buffer and Snapshot returns them in order.
func TestStoreAppendWritesToRingBuffer(t *testing.T) {
	t.Parallel()
	st := NewStore()

	st.Append(Entry{Action: "node.registered", NetworkID: 42, NodeID: 7})
	st.Append(Entry{Action: "network.created", NetworkID: 1})

	snap := st.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snap))
	}
	if snap[0].Action != "node.registered" {
		t.Errorf("snap[0].Action = %q, want node.registered", snap[0].Action)
	}
	if snap[1].Action != "network.created" {
		t.Errorf("snap[1].Action = %q, want network.created", snap[1].Action)
	}
}

// TestStoreSubscribeForwardsToExporter verifies that publishing "audit.entry"
// events to the bus causes the Store subscriber goroutine to forward entries
// to the configured exporter (not to the ring buffer).
func TestStoreSubscribeForwardsToExporter(t *testing.T) {
	t.Parallel()
	var hits atomic.Uint64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bus := events.NewInProcessBus(0)
	st := NewStore()
	st.Subscribe(bus)
	defer st.Close()
	st.SetExporter(&wire.BlueprintAuditExport{Format: "json", Endpoint: srv.URL})

	// Ring buffer should be empty (bus events don't write to it).
	bus.Publish(events.Event{
		Source: "test",
		Type:   "audit.entry",
		Payload: map[string]any{
			"action":     "test.action",
			"network_id": uint16(5),
			"node_id":    uint32(99),
			"details":    "",
			"timestamp":  time.Now().UTC().Format(time.RFC3339),
		},
	})

	// Wait for exporter to receive the entry.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hits.Load() == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if hits.Load() != 1 {
		t.Fatalf("exporter hits = %d, want 1", hits.Load())
	}

	// Ring buffer should remain empty (bus events go only to exporter).
	if snap := st.Snapshot(); len(snap) != 0 {
		t.Fatalf("ring buffer len = %d after bus event, want 0 (exporter-only fan-out)", len(snap))
	}
}

// TestStoreFilteredEntriesNewestFirst verifies filtering and ordering of Append entries.
func TestStoreFilteredEntriesNewestFirst(t *testing.T) {
	t.Parallel()
	st := NewStore()

	// Append 5 entries with two different network IDs.
	for i := 0; i < 5; i++ {
		netID := uint16(1)
		if i%2 == 0 {
			netID = 2
		}
		st.Append(Entry{Action: "action", NetworkID: netID, NodeID: uint32(i)})
	}

	// FilteredEntries(netID=2, limit=10) should return 3 entries (i=0,2,4),
	// newest first.
	entries := st.FilteredEntries(2, 10)
	if len(entries) != 3 {
		t.Fatalf("filtered len = %d, want 3", len(entries))
	}
	// The first returned entry should have the highest node_id (4).
	if nid, _ := entries[0]["node_id"].(uint32); nid != 4 {
		t.Errorf("entries[0].node_id = %v, want 4", entries[0]["node_id"])
	}
}

// TestStoreRestoreLog verifies that RestoreLog replaces the ring buffer.
func TestStoreRestoreLog(t *testing.T) {
	t.Parallel()
	st := NewStore()
	restored := []Entry{
		{Timestamp: "2026-01-01T00:00:00Z", Action: "old.event", NetworkID: 5, NodeID: 9},
		{Timestamp: "2026-01-02T00:00:00Z", Action: "old.event2"},
	}
	st.RestoreLog(restored)

	snap := st.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snap len = %d after RestoreLog, want 2", len(snap))
	}
	if snap[0].Action != "old.event" || snap[1].Action != "old.event2" {
		t.Errorf("unexpected restored entries: %v", snap)
	}
}

// TestStoreHandleGetAuditExportDisabled verifies the response when no exporter
// is configured.
func TestStoreHandleGetAuditExportDisabled(t *testing.T) {
	t.Parallel()
	st := NewStore()
	resp, err := st.HandleGetAuditExport(nil)
	if err != nil {
		t.Fatalf("HandleGetAuditExport: %v", err)
	}
	if enabled, _ := resp["enabled"].(bool); enabled {
		t.Fatalf("enabled = true, want false when no exporter configured")
	}
	if tp, _ := resp["type"].(string); tp != "get_audit_export_ok" {
		t.Fatalf("type = %q, want get_audit_export_ok", tp)
	}
}

// ---------------------------------------------------------------------------
// BuildEntry helper
// ---------------------------------------------------------------------------

func TestBuildEntryExtractsNodeAndNetworkID(t *testing.T) {
	t.Parallel()
	e := BuildEntry("node.joined", 0, 0,
		"node_id", uint32(42),
		"network_id", uint16(7),
		"extra", "val",
	)
	if e.NodeID != 42 {
		t.Errorf("NodeID = %d, want 42", e.NodeID)
	}
	if e.NetworkID != 7 {
		t.Errorf("NetworkID = %d, want 7", e.NetworkID)
	}
	if !strings.Contains(e.Details, "extra=val") {
		t.Errorf("Details = %q, want to contain extra=val", e.Details)
	}
	if e.Action != "node.joined" {
		t.Errorf("Action = %q, want node.joined", e.Action)
	}
}

// ---------------------------------------------------------------------------
// AuditExporter white-box format tests (internal package access)
// ---------------------------------------------------------------------------

func TestFormatSplunkHECEmitsExpectedFields(t *testing.T) {
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{
		Format: "splunk_hec", Source: "", Index: "pilot-audit",
	}}
	ts := time.Now().UTC().Truncate(time.Second)
	body, err := ae.formatSplunkHEC(&Entry{
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
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{
		Format: "splunk_hec", Source: "custom-host",
	}}
	body, err := ae.formatSplunkHEC(&Entry{Action: "a"})
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
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{Format: "splunk_hec"}}
	before := time.Now().Unix()
	body, err := ae.formatSplunkHEC(&Entry{Action: "a", Timestamp: ""})
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
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{Format: "splunk_hec"}}
	body, err := ae.formatSplunkHEC(&Entry{
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

func TestFormatCEFSeverityInformationalForNormalActions(t *testing.T) {
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{Format: "syslog_cef"}}
	body, err := ae.formatCEF(&Entry{Action: "register", NetworkID: 5, NodeID: 12})
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
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{Format: "syslog_cef"}}
	for _, action := range []string{"kick_member", "delete_network", "member_kick"} {
		body, _ := ae.formatCEF(&Entry{Action: action})
		line := string(body)
		if !strings.Contains(line, "|"+action+"|"+action+"|6|") {
			t.Fatalf("action %q severity != 6, got: %s", action, line)
		}
	}
}

func TestFormatCEFSeverityMediumForPromoteDemote(t *testing.T) {
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{Format: "syslog_cef"}}
	for _, action := range []string{"promote_admin", "demote_member"} {
		body, _ := ae.formatCEF(&Entry{Action: action})
		line := string(body)
		if !strings.Contains(line, "|"+action+"|"+action+"|4|") {
			t.Fatalf("action %q severity != 4, got: %s", action, line)
		}
	}
}

func TestFormatCEFAppendsMsgWhenDetailsSet(t *testing.T) {
	t.Parallel()
	ae := &AuditExporter{config: &wire.BlueprintAuditExport{Format: "syslog_cef"}}
	body, _ := ae.formatCEF(&Entry{Action: "register", Details: "by-op"})
	line := string(body)
	if !strings.HasSuffix(line, " msg=by-op") {
		t.Fatalf("expected trailing msg=by-op, got: %s", line)
	}
}

// TestAuditExporterExportBufferFullIncrementsDropped verifies the drop counter
// when the export channel fills up.
func TestAuditExporterExportBufferFullIncrementsDropped(t *testing.T) {
	t.Parallel()
	ae := &AuditExporter{
		config: &wire.BlueprintAuditExport{Format: "json", Endpoint: ""},
		ch:     make(chan *Entry, 4), // tiny buffer
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	for i := 0; i < 20; i++ {
		ae.Export(&Entry{Action: "flood", NodeID: uint32(i)})
	}
	_, dropped := ae.Stats()
	if dropped == 0 {
		t.Fatalf("dropped = 0 after 20 Exports into 4-buffer, want > 0")
	}
	if dropped < 16 {
		t.Fatalf("dropped = %d, want >= 16 (20 sent - 4 buffered)", dropped)
	}
}

// TestSendUnknownFormatUsesJSON verifies the default JSON fallback.
func TestSendUnknownFormatUsesJSON(t *testing.T) {
	t.Parallel()
	entry := &Entry{Action: "default-fmt", NetworkID: 1, NodeID: 2}
	body, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var out Entry
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if out.Action != "default-fmt" {
		t.Fatalf("Action = %q, want default-fmt", out.Action)
	}
}
