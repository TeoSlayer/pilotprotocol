// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/registry/wire"
)

// AuditExporter sends audit events to an external system in the configured
// format (Splunk HEC, syslog/CEF, or plain JSON). It runs asynchronously
// with a buffered channel, just like registryWebhook.
type AuditExporter struct {
	config    *wire.BlueprintAuditExport
	ch        chan *Entry
	client    *http.Client
	done      chan struct{}
	closeOnce sync.Once
	closed    chan struct{}
	exported  atomic.Uint64
	dropped   atomic.Uint64
}

// NewAuditExporter creates and starts a new AuditExporter for the given config.
// It is exported so that the server package shim (audit_export.go) can
// delegate to it without the sub-package re-implementing the constructor.
func NewAuditExporter(cfg *wire.BlueprintAuditExport) *AuditExporter {
	return newAuditExporter(cfg)
}

func newAuditExporter(cfg *wire.BlueprintAuditExport) *AuditExporter {
	ae := &AuditExporter{
		config: cfg,
		ch:     make(chan *Entry, 1024),
		client: &http.Client{Timeout: 10 * time.Second},
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	go ae.run()
	return ae
}

// Export queues an audit entry for export. Non-blocking; drops if buffer full.
func (ae *AuditExporter) Export(entry *Entry) {
	if ae == nil {
		return
	}
	select {
	case <-ae.closed:
		return
	default:
	}
	select {
	case ae.ch <- entry:
	case <-ae.closed:
	default:
		ae.dropped.Add(1)
	}
}

// Close signals the background goroutine to stop and waits for it to drain.
func (ae *AuditExporter) Close() {
	if ae == nil {
		return
	}
	ae.closeOnce.Do(func() {
		// Only close ae.closed — never close ae.ch here. Closing ae.ch while
		// Export() may concurrently be sending on it causes a race: Export's
		// two-step "check closed, then send" has a window where ae.ch gets
		// closed between the check and the send.
		close(ae.closed)
	})
	select {
	case <-ae.done:
	case <-time.After(5 * time.Second):
		slog.Warn("audit exporter drain timeout")
	}
}

func (ae *AuditExporter) run() {
	defer close(ae.done)
	for {
		select {
		case entry := <-ae.ch:
			ae.send(entry)
		case <-ae.closed:
			// drain whatever is already buffered
			for {
				select {
				case entry := <-ae.ch:
					ae.send(entry)
				default:
					return
				}
			}
		}
	}
}

func (ae *AuditExporter) send(entry *Entry) {
	var body []byte
	var contentType string
	var err error

	switch ae.config.Format {
	case "splunk_hec":
		body, err = ae.formatSplunkHEC(entry)
		contentType = "application/json"
	case "syslog_cef":
		body, err = ae.formatCEF(entry)
		contentType = "text/plain"
	default: // "json"
		body, err = json.Marshal(entry)
		contentType = "application/json"
	}
	if err != nil {
		slog.Warn("audit export format error", "format", ae.config.Format, "error", err)
		return
	}

	req, err := http.NewRequest("POST", ae.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("audit export request error", "error", err)
		return
	}
	req.Header.Set("Content-Type", contentType)

	// Splunk HEC requires Authorization header
	if ae.config.Token != "" {
		req.Header.Set("Authorization", "Splunk "+ae.config.Token)
	}

	backoff := time.Second
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		resp, err := ae.client.Do(req)
		if err != nil {
			slog.Warn("audit export POST failed", "attempt", attempt+1, "error", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			ae.exported.Add(1)
			return
		}
		if resp.StatusCode < 500 {
			slog.Warn("audit export client error", "status", resp.StatusCode)
			return
		}
		slog.Warn("audit export server error", "status", resp.StatusCode, "attempt", attempt+1)
	}
}

// SplunkHECEvent is the Splunk HTTP Event Collector event format.
type SplunkHECEvent struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host,omitempty"`
	Source     string                 `json:"source,omitempty"`
	SourceType string                 `json:"sourcetype,omitempty"`
	Index      string                 `json:"index,omitempty"`
	Event      map[string]interface{} `json:"event"`
}

func (ae *AuditExporter) formatSplunkHEC(entry *Entry) ([]byte, error) {
	t, _ := time.Parse(time.RFC3339, entry.Timestamp)
	if t.IsZero() {
		t = time.Now()
	}

	event := map[string]interface{}{
		"action":     entry.Action,
		"network_id": entry.NetworkID,
		"node_id":    entry.NodeID,
	}
	if entry.Details != "" {
		event["details"] = entry.Details
	}

	hec := SplunkHECEvent{
		Time:       t.Unix(),
		Source:     ae.config.Source,
		SourceType: "pilot:audit",
		Index:      ae.config.Index,
		Event:      event,
	}
	if hec.Source == "" {
		hec.Source = "pilot-registry"
	}

	return json.Marshal(hec)
}

// formatCEF produces a CEF (Common Event Format) line for SIEM ingestion.
// Format: CEF:0|Pilot|Registry|1.0|<action>|<action>|<severity>|<extensions>
func (ae *AuditExporter) formatCEF(entry *Entry) ([]byte, error) {
	severity := 3 // informational
	if strings.Contains(entry.Action, "kick") || strings.Contains(entry.Action, "delete") {
		severity = 6 // high
	} else if strings.Contains(entry.Action, "promote") || strings.Contains(entry.Action, "demote") {
		severity = 4 // medium
	}

	extensions := fmt.Sprintf("dvc=pilot-registry dvchost=registry "+
		"cs1=%s cs1Label=action cn1=%d cn1Label=network_id cn2=%d cn2Label=node_id",
		entry.Action, entry.NetworkID, entry.NodeID)

	if entry.Details != "" {
		extensions += fmt.Sprintf(" msg=%s", entry.Details)
	}

	line := fmt.Sprintf("CEF:0|Pilot|Registry|1.0|%s|%s|%d|%s",
		entry.Action, entry.Action, severity, extensions)

	return []byte(line), nil
}

// Stats returns export statistics.
func (ae *AuditExporter) Stats() (exported, dropped uint64) {
	if ae == nil {
		return 0, 0
	}
	return ae.exported.Load(), ae.dropped.Load()
}
