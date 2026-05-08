// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dashboard implements the HTTP dashboard server, probe loop, and
// pulse-sample ring for the Pilot Protocol registry. It is extracted from
// pkg/registry/server as part of the R5.1 registry decomposition.
//
// Thread safety: all exported Handler methods are safe for concurrent use.
package dashboard

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// --------------------------------------------------------------------------
// Probe state
// --------------------------------------------------------------------------

// ProbeState holds the health history for a single named probe.
type ProbeState struct {
	LastSuccess       int64      `json:"last_success,omitempty"`       // millis
	DowntimeIntervals [][2]int64 `json:"downtime_intervals,omitempty"` // pruned to 30d
	CurrentDownStart  int64      `json:"current_down_start,omitempty"` // 0 when up
}

// ProbeRetention is the maximum age of probe downtime intervals kept in memory
// and persisted to snapshots.
const ProbeRetention = 30 * 24 * time.Hour

const probeRetention = ProbeRetention

// PulseSample is one entry in the server-side 1/sec request-count ring.
type PulseSample struct {
	Ts    int64 `json:"ts"`
	Total int64 `json:"total"`
}

// --------------------------------------------------------------------------
// Callbacks
// --------------------------------------------------------------------------

// Callbacks bundles the side-effect functions Handler calls on the parent server.
// All functions must be safe for concurrent use.
type Callbacks struct {
	// GetDashboardToken returns the current dashboard token.
	GetDashboardToken func() string
	// GetAdminToken returns the current admin token.
	GetAdminToken func() string
	// BuildStatsPayload assembles the core /api/stats JSON payload (without
	// probe state and maintenance banner, which are owned by Handler).
	// The returned map is JSON-safe; callers must not mutate it.
	BuildStatsPayload func(authenticated bool) map[string]interface{}
	// GetNodes returns a snapshot of registered nodes for /api/nodes.
	GetNodes func() []NodeSnapshot
	// RequestCount returns the current total request count.
	RequestCount func() int64
	// StartTime returns when the server started.
	StartTime func() time.Time
	// NodeCount returns the number of registered nodes.
	NodeCount func() int
	// OnlineCount returns the number of nodes online at or after threshold.
	OnlineCount func(threshold time.Time) int
	// StaleThreshold returns the configured stale-node threshold.
	StaleThreshold func() time.Duration
	// TriggerSnapshot triggers a snapshot save.
	TriggerSnapshot func() error
	// UpdateGauges updates Prometheus gauges before /metrics scrape.
	UpdateGauges func()
	// WriteMetrics writes Prometheus metrics to w.
	WriteMetrics func(w io.Writer)
	// ListenerAddr returns the registry TCP listener address for probeRegistry.
	// Returns "" when no listener is bound.
	ListenerAddr func() string
	// BeaconAddr returns the beacon UDP address for probeBeacon. "" = disabled.
	BeaconAddr func() string
	// ReadyCh returns the channel closed when the server is ready.
	ReadyCh func() <-chan struct{}
	// Done returns the channel closed on server shutdown.
	Done func() <-chan struct{}
	// Save triggers a debounced snapshot after probe state changes.
	Save func()
}

// NodeSnapshot is a minimal node record for the /api/nodes endpoint.
type NodeSnapshot struct {
	ID       uint32
	Hostname string
	LastSeen time.Time
}

// --------------------------------------------------------------------------
// Handler
// --------------------------------------------------------------------------

// Handler owns the dashboard HTTP mux, probe state, pulse ring, and the
// maintenance banner. It is wired into the parent server via Callbacks.
type Handler struct {
	cb Callbacks

	// Maintenance banner (operator notice rendered on dashboard).
	bannerMu          sync.RWMutex
	maintenanceBanner string
	bannerPath        string

	// Probe state — per-probe health history ring.
	probeMu       sync.Mutex
	probeStates   map[string]*ProbeState
	httpProbeAddr string // injected via SetHTTPProbeAddr

	// Pulse ring — 2-minute 1/sec request-count sample ring.
	pulseMu      sync.Mutex
	pulseSamples [120]PulseSample
	pulseIdx     int
	pulseFilled  bool
}

// NewHandler creates a ready-to-use dashboard Handler backed by cb.
func NewHandler(cb Callbacks) *Handler {
	return &Handler{cb: cb}
}

// --------------------------------------------------------------------------
// Maintenance banner
// --------------------------------------------------------------------------

// SetMaintenanceBanner sets a free-form notice rendered on the dashboard.
// Empty string clears it. If a bannerPath has been configured, the new
// value is atomically written to disk.
func (h *Handler) SetMaintenanceBanner(msg string) {
	h.bannerMu.Lock()
	h.maintenanceBanner = msg
	bp := h.bannerPath
	h.bannerMu.Unlock()
	if bp != "" {
		tmp := bp + ".tmp"
		if err := os.WriteFile(tmp, []byte(msg), 0644); err != nil {
			slog.Warn("banner persist write failed", "path", bp, "err", err)
			return
		}
		if err := os.Rename(tmp, bp); err != nil {
			slog.Warn("banner persist rename failed", "path", bp, "err", err)
		}
	}
}

// MaintenanceBanner returns the currently-set maintenance notice (or "").
func (h *Handler) MaintenanceBanner() string {
	h.bannerMu.RLock()
	defer h.bannerMu.RUnlock()
	return h.maintenanceBanner
}

// SetBannerPath wires a disk-persistence path for the maintenance banner.
// If the file already exists, its contents become the in-memory banner.
func (h *Handler) SetBannerPath(path string) {
	h.bannerMu.Lock()
	h.bannerPath = path
	h.bannerMu.Unlock()
	if data, err := os.ReadFile(path); err == nil {
		msg := strings.TrimRight(string(data), "\r\n")
		h.bannerMu.Lock()
		h.maintenanceBanner = msg
		h.bannerMu.Unlock()
	}
}

// --------------------------------------------------------------------------
// HTTP probe address
// --------------------------------------------------------------------------

// SetHTTPProbeAddr records the dashboard HTTP listen address so the probe
// loop knows where to dial for the dashboard + metrics probes.
func (h *Handler) SetHTTPProbeAddr(addr string) {
	h.probeMu.Lock()
	h.httpProbeAddr = addr
	h.probeMu.Unlock()
}

// --------------------------------------------------------------------------
// Probe state management
// --------------------------------------------------------------------------

var probeNames = []string{"registry", "beacon", "dashboard", "metrics"} //nolint:unused

func (h *Handler) runProbe(name string, ok bool) {
	now := time.Now().UnixMilli()
	cutoff := time.Now().Add(-probeRetention).UnixMilli()
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if h.probeStates == nil {
		h.probeStates = map[string]*ProbeState{}
	}
	p := h.probeStates[name]
	if p == nil {
		p = &ProbeState{}
		h.probeStates[name] = p
	}
	// Prune intervals older than the retention window.
	if len(p.DowntimeIntervals) > 0 {
		kept := p.DowntimeIntervals[:0]
		for _, iv := range p.DowntimeIntervals {
			if iv[1] >= cutoff {
				kept = append(kept, iv)
			}
		}
		p.DowntimeIntervals = kept
	}
	if ok {
		p.LastSuccess = now
		if p.CurrentDownStart > 0 {
			p.DowntimeIntervals = append(p.DowntimeIntervals, [2]int64{p.CurrentDownStart, now})
			p.CurrentDownStart = 0
		}
	} else {
		if p.CurrentDownStart == 0 {
			p.CurrentDownStart = now
		}
	}
}

// GetProbeStates returns a deep-copy snapshot of all probe states.
func (h *Handler) GetProbeStates() map[string]*ProbeState {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	if len(h.probeStates) == 0 {
		return nil
	}
	out := make(map[string]*ProbeState, len(h.probeStates))
	for k, v := range h.probeStates {
		cp := *v
		if len(v.DowntimeIntervals) > 0 {
			cp.DowntimeIntervals = append([][2]int64(nil), v.DowntimeIntervals...)
		}
		out[k] = &cp
	}
	return out
}

// SetProbeStates replaces the probe state map (used during snapshot restore).
func (h *Handler) SetProbeStates(states map[string]*ProbeState) {
	h.probeMu.Lock()
	h.probeStates = states
	h.probeMu.Unlock()
}

// --------------------------------------------------------------------------
// Individual probes
// --------------------------------------------------------------------------

func (h *Handler) probeRegistry() bool {
	addr := h.cb.ListenerAddr()
	if addr == "" {
		return false
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (h *Handler) probeBeacon() bool {
	beaconAddr := h.cb.BeaconAddr()
	if beaconAddr == "" {
		return false
	}
	target, err := net.ResolveUDPAddr("udp", beaconAddr)
	if err != nil {
		return false
	}
	c, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return false
	}
	defer c.Close()
	// Reserved probe nodeID — kept high so it doesn't collide with real nodes.
	msg := make([]byte, 5)
	msg[0] = protocol.BeaconMsgDiscover
	binary.BigEndian.PutUint32(msg[1:], 0xFFFFFFFE)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || n < 1 || buf[0] != protocol.BeaconMsgDiscoverReply {
		return false
	}
	return true
}

func (h *Handler) probeHTTP(path string) bool {
	h.probeMu.Lock()
	addr := h.httpProbeAddr
	h.probeMu.Unlock()
	if addr == "" {
		return false
	}
	if addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "http://"+addr+path, nil)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// ProbeLoop runs the 4 component probes at a steady cadence. Must be called
// in a separate goroutine (typically by the parent server).
func (h *Handler) ProbeLoop() {
	<-h.cb.ReadyCh()
	// Give listeners a moment to bind before first probe.
	time.Sleep(500 * time.Millisecond)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	tick := func() {
		h.runProbe("registry", h.probeRegistry())
		h.runProbe("beacon", h.probeBeacon())
		h.runProbe("dashboard", h.probeHTTP("/healthz"))
		h.runProbe("metrics", h.probeHTTP("/metrics"))
		if h.cb.Save != nil {
			h.cb.Save()
		}
	}
	tick()
	for {
		select {
		case <-t.C:
			tick()
		case <-h.cb.Done():
			return
		}
	}
}

// --------------------------------------------------------------------------
// Pulse ring
// --------------------------------------------------------------------------

// GetPulseSamples returns the ordered pulse samples from the ring buffer.
func (h *Handler) GetPulseSamples() []PulseSample {
	h.pulseMu.Lock()
	defer h.pulseMu.Unlock()
	n := len(h.pulseSamples)
	if !h.pulseFilled {
		out := make([]PulseSample, h.pulseIdx)
		copy(out, h.pulseSamples[:h.pulseIdx])
		return out
	}
	out := make([]PulseSample, 0, n)
	out = append(out, h.pulseSamples[h.pulseIdx:]...)
	out = append(out, h.pulseSamples[:h.pulseIdx]...)
	return out
}

// PulseLoop records one request-count sample per second into the ring.
// Must be called in a separate goroutine.
func (h *Handler) PulseLoop() {
	<-h.cb.ReadyCh()
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			sample := PulseSample{Ts: time.Now().UnixMilli(), Total: h.cb.RequestCount()}
			h.pulseMu.Lock()
			h.pulseSamples[h.pulseIdx] = sample
			h.pulseIdx++
			if h.pulseIdx >= len(h.pulseSamples) {
				h.pulseIdx = 0
				h.pulseFilled = true
			}
			h.pulseMu.Unlock()
		case <-h.cb.Done():
			return
		}
	}
}

// --------------------------------------------------------------------------
// HTTP helpers
// --------------------------------------------------------------------------

// readSmallBody reads up to maxBytes of the request body and trims trailing
// whitespace. Used by admin write endpoints.
func readSmallBody(r *http.Request, maxBytes int64) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > maxBytes {
		return "", fmt.Errorf("body too large (max %d bytes)", maxBytes)
	}
	return strings.TrimRight(string(data), "\r\n\t "), nil
}

// localhostOnly rejects requests not originating from loopback.
// Trusts X-Real-IP only when the direct connection is from localhost.
func localhostOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		clientIP := remoteIP
		if remoteIP == "127.0.0.1" || remoteIP == "::1" || remoteIP == "localhost" {
			if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				clientIP = realIP
			}
		}
		if clientIP != "127.0.0.1" && clientIP != "::1" && clientIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// --------------------------------------------------------------------------
// Serve
// --------------------------------------------------------------------------

// Serve starts an HTTP server serving the dashboard UI and stats API.
func (h *Handler) Serve(addr string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		authenticated := false
		if token := r.URL.Query().Get("token"); token != "" {
			dt := h.cb.GetDashboardToken()
			if dt != "" && subtle.ConstantTimeCompare([]byte(token), []byte(dt)) == 1 {
				authenticated = true
			}
		}
		_ = json.NewEncoder(w).Encode(h.buildStatsResponse(authenticated))
	})

	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		clientIP := remoteIP
		if remoteIP == "127.0.0.1" || remoteIP == "::1" || remoteIP == "localhost" {
			if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				clientIP = realIP
			}
		}
		if clientIP != "127.0.0.1" && clientIP != "::1" && clientIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		nodes := h.cb.GetNodes()
		items := make([]map[string]interface{}, 0, len(nodes))
		for _, node := range nodes {
			entry := map[string]interface{}{
				"node_id": node.ID,
				"address": protocol.Addr{Network: 0, Node: node.ID}.String(),
			}
			if node.Hostname != "" {
				entry["hostname"] = node.Hostname
			}
			entry["last_seen"] = node.LastSeen.Format(time.RFC3339)
			items = append(items, entry)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": items,
			"count": len(items),
		})
	})

	// /api/banner — admin-only management endpoint for the dashboard notice.
	// Both GET and PUT require the admin token (header X-Admin-Token or
	// query admin_token=). PUT body is the new banner text (empty = clear).
	mux.HandleFunc("/api/banner", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = r.URL.Query().Get("admin_token")
		}
		adminToken := h.cb.GetAdminToken()
		if adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"banner": h.MaintenanceBanner(),
			})
		case http.MethodPut, http.MethodPost:
			body, err := readSmallBody(r, 8192)
			if err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			h.SetMaintenanceBanner(body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":     true,
				"banner": body,
			})
		default:
			w.Header().Set("Allow", "GET, PUT, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/pulse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ts":             time.Now().UnixMilli(),
			"total_requests": h.cb.RequestCount(),
			"samples":        h.GetPulseSamples(),
		})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		nodeCount := h.cb.NodeCount()
		startTime := h.cb.StartTime()
		now := time.Now()
		onlineThreshold := now.Add(-h.cb.StaleThreshold())
		online := h.cb.OnlineCount(onlineThreshold)

		// Registry is healthy as long as it is running.
		healthy := nodeCount >= 0
		status := http.StatusOK
		statusStr := "ok"
		if !healthy {
			status = http.StatusServiceUnavailable
			statusStr = "unhealthy"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         statusStr,
			"version":        "1.0",
			"uptime_seconds": int64(now.Sub(startTime).Seconds()),
			"nodes_online":   online,
		})
	})

	serveBadge := func(w http.ResponseWriter, label, value, color string) {
		lw := int(float64(len(label))*6.5) + 10
		vw := int(float64(len(value))*6.5) + 10
		tw := lw + vw
		svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">`+
			`<title>%s: %s</title>`+
			`<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`+
			`<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>`+
			`<g clip-path="url(#r)">`+
			`<rect width="%d" height="20" fill="#555"/>`+
			`<rect x="%d" width="%d" height="20" fill="%s"/>`+
			`<rect width="%d" height="20" fill="url(#s)"/>`+
			`</g>`+
			`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">`+
			`<text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">%s</text>`+
			`<text x="%d" y="140" transform="scale(.1)">%s</text>`+
			`<text aria-hidden="true" x="%d" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">%s</text>`+
			`<text x="%d" y="140" transform="scale(.1)">%s</text>`+
			`</g></svg>`,
			tw, label, value,
			label, value,
			tw,
			lw,
			lw, vw, color,
			tw,
			lw*5, label,
			lw*5, label,
			lw*10+vw*5, value,
			lw*10+vw*5, value,
		)
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write([]byte(svg))
	}

	fmtCount := func(n int) string {
		switch {
		case n >= 1e9:
			return fmt.Sprintf("%.1fB", float64(n)/1e9)
		case n >= 1e6:
			return fmt.Sprintf("%.1fM", float64(n)/1e6)
		case n >= 1e3:
			return fmt.Sprintf("%.1fK", float64(n)/1e3)
		default:
			return fmt.Sprintf("%d", n)
		}
	}

	mux.HandleFunc("/api/badge/nodes", func(w http.ResponseWriter, r *http.Request) {
		payload := h.cb.BuildStatsPayload(false)
		activeNodes, _ := payload["active_nodes"].(int)
		c := "#4c1"
		if activeNodes == 0 {
			c = "#9f9f9f"
		}
		serveBadge(w, "online nodes", fmtCount(activeNodes), c)
	})

	mux.HandleFunc("/api/badge/requests", func(w http.ResponseWriter, r *http.Request) {
		payload := h.cb.BuildStatsPayload(false)
		totalReqs, _ := payload["total_requests"].(int64)
		serveBadge(w, "requests", fmtCount(int(totalReqs)), "#a855f7")
	})

	// Snapshot trigger endpoint (POST only, localhost only).
	mux.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		clientIP := remoteIP
		if remoteIP == "127.0.0.1" || remoteIP == "::1" || remoteIP == "localhost" {
			if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
				clientIP = realIP
			}
		}
		if clientIP != "127.0.0.1" && clientIP != "::1" && clientIP != "localhost" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := h.cb.TriggerSnapshot(); err != nil {
			http.Error(w, fmt.Sprintf("snapshot failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": "snapshot saved successfully",
		})
	})

	// Prometheus metrics endpoint (localhost only — scraped by Alloy on the same host).
	mux.HandleFunc("/metrics", localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		h.cb.UpdateGauges()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		h.cb.WriteMetrics(w)
	}))

	// pprof endpoints for live profiling (localhost only).
	mux.HandleFunc("/debug/pprof/", localhostOnly(pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", localhostOnly(pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", localhostOnly(pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", localhostOnly(pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", localhostOnly(pprof.Trace))

	slog.Info("dashboard listening", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

// --------------------------------------------------------------------------
// Stats response assembly
// --------------------------------------------------------------------------

// buildStatsResponse assembles the /api/stats JSON payload by merging the
// core stats from BuildStatsPayload with the probe state and maintenance
// banner owned by Handler.
func (h *Handler) buildStatsResponse(authenticated bool) map[string]interface{} {
	payload := h.cb.BuildStatsPayload(authenticated)
	// Overlay maintenance_banner from Handler (operator notice managed here).
	payload["maintenance_banner"] = h.MaintenanceBanner()
	// Overlay probe state from Handler (moved off Server in R5.1).
	if probes := h.GetProbeStates(); len(probes) > 0 {
		payload["probes"] = probes
	}
	return payload
}

// --------------------------------------------------------------------------
// Dashboard HTML
// --------------------------------------------------------------------------

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pilot Protocol — Network Status</title>
<style>
:root{
  --bg:#0a0e17; --panel:#161b22; --panel2:#0d1117;
  --border:#21262d; --border2:#30363d;
  --text:#c9d1d9; --text2:#e6edf3;
  --muted:#8b949e; --muted2:#484f58;
  --accent:#58a6ff; --good:#3fb950;
  --grid:#21262d;
}
html[data-theme="light"]{
  --bg:#ffffff; --panel:#f6f8fa; --panel2:#ffffff;
  --border:#d0d7de; --border2:#afb8c1;
  --text:#1f2328; --text2:#0d1117;
  --muted:#656d76; --muted2:#8c959f;
  --accent:#0969da; --good:#1a7f37;
  --grid:#d8dee4;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:'SF Mono','Fira Code','Cascadia Code',monospace;font-size:14px;line-height:1.6;transition:background 0.2s,color 0.2s}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

.container{max-width:960px;margin:0 auto;padding:24px 16px}

header{padding:16px 0;border-bottom:1px solid var(--border);margin-bottom:32px;display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
header h1{font-size:20px;font-weight:600;color:var(--text2)}
.uptime{font-size:12px;color:var(--muted);margin-top:4px}
.svc-bar-wrap{position:relative;display:inline-block}
.svc-bar-tip{position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--border2);border-radius:4px;padding:6px 9px;font-size:11px;color:var(--text);white-space:nowrap;z-index:50;box-shadow:0 4px 12px rgba(0,0,0,0.3);pointer-events:none;display:none}
.svc-bar-wrap:hover .svc-bar-tip{display:block}
.svc-bar-tip .v{color:var(--text2);font-variant-numeric:tabular-nums}
.svc-bar.partial{background:#f59e0b;opacity:0.85}
.svc-bar.down{background:#ef4444;opacity:0.9}
.svc-bar.inactive{background:var(--border);opacity:0.4}
.banner-stack{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.release-banner{background:linear-gradient(90deg,rgba(88,166,255,0.12),rgba(88,166,255,0.04));border:1px solid rgba(88,166,255,0.4);border-left:3px solid var(--accent);border-radius:6px;padding:10px 14px;font-size:13px;color:var(--text);display:flex;align-items:center;gap:10px}
.release-banner.maintenance{background:linear-gradient(90deg,rgba(245,158,11,0.14),rgba(245,158,11,0.04));border:1px solid rgba(245,158,11,0.45);border-left:3px solid #f59e0b}
.release-banner .rb-dot{width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px var(--accent);flex-shrink:0;animation:rbPulse 2s ease-in-out infinite}
.release-banner.maintenance .rb-dot{background:#f59e0b;box-shadow:0 0 8px #f59e0b}
.release-banner .rb-ver{color:var(--text2);font-weight:600}
.release-banner .rb-label{font-weight:600;margin-right:4px}
@keyframes rbPulse{0%,100%{opacity:1}50%{opacity:0.45}}
.theme-toggle{background:var(--panel);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:6px 10px;font-family:inherit;font-size:12px;cursor:pointer;line-height:1}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}

.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:var(--text2);display:block}
.stat-card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}

.token-bar{display:flex;align-items:center;gap:8px;margin-top:8px}
.token-bar input{background:var(--panel2);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-family:inherit;font-size:12px;width:180px}
.token-bar input::placeholder{color:var(--muted2)}
.token-bar button{background:var(--panel);border:1px solid var(--border2);border-radius:4px;color:var(--text);padding:4px 10px;font-family:inherit;font-size:12px;cursor:pointer}
.token-bar button:hover{border-color:var(--accent);color:var(--accent)}
.token-bar .status{font-size:11px;color:var(--muted2)}
.token-bar .status.ok{color:var(--good)}

.networks{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:32px;display:none}
.networks h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.networks table{width:100%;border-collapse:collapse}
.networks th{text-align:left;font-size:11px;color:var(--muted2);text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid var(--border)}
.networks td{font-size:13px;color:var(--text);padding:6px 8px;border-bottom:1px solid var(--panel)}
.networks tr:hover td{background:var(--panel2)}
.net-id{color:var(--muted);font-size:11px}

.system-row{display:grid;grid-template-columns:3fr 2fr;gap:16px;margin-bottom:32px}
.system-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px}
.system-card h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}

.svc-row{display:grid;grid-template-columns:140px 1fr auto;gap:12px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)}
.svc-row:last-child{border-bottom:none}
.svc-name{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text)}
.svc-dot{width:8px;height:8px;border-radius:50%;background:var(--good);box-shadow:0 0 6px var(--good)}
.svc-dot.degraded{background:#f59e0b;box-shadow:0 0 6px #f59e0b}
.svc-dot.down{background:#ef4444;box-shadow:0 0 6px #ef4444}
.svc-bars{display:flex;gap:1px;height:28px}
.svc-bar-wrap{flex:1;position:relative;display:block;height:100%}
.svc-bar{display:block;width:100%;height:100%;background:var(--good);border-radius:1px;opacity:0.85;transition:opacity 0.2s}
.svc-bar-wrap:hover .svc-bar{opacity:1}
.svc-bar.unknown{background:var(--border2);opacity:0.4}
.svc-bar.degraded{background:#f59e0b}
.svc-bar.blip{background:#f59e0b;opacity:1;box-shadow:0 0 5px rgba(245,158,11,0.7)}
.svc-uptime{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;min-width:60px;text-align:right}

.pulse-wrap{display:flex;align-items:baseline;gap:6px;margin-bottom:8px}
.pulse-val{font-size:28px;font-weight:700;color:var(--text2);font-variant-numeric:tabular-nums}
.pulse-unit{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px}
.pulse-strip{display:flex;align-items:flex-end;gap:1px;height:48px;background:var(--panel2);border:1px solid var(--border);border-radius:4px;padding:4px}
.pulse-bar{flex:1;background:var(--accent);border-radius:1px 1px 0 0;min-height:1px;opacity:0.7}
.pulse-bar.live{opacity:1;filter:drop-shadow(0 0 4px var(--accent));animation:pulseGlow 1.2s ease-in-out infinite alternate}
@keyframes pulseGlow{from{opacity:0.7;filter:drop-shadow(0 0 2px var(--accent))}to{opacity:1;filter:drop-shadow(0 0 6px var(--accent))}}
.pulse-meta{font-size:11px;color:var(--muted2);margin-top:6px;display:flex;justify-content:space-between}

@media(max-width:640px){
  .system-row{grid-template-columns:1fr}
}


.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:32px}
.chart-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px}
.chart-card.full{grid-column:1/-1}
.chart-card h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.chart-card .disclaimer{font-size:11px;color:var(--muted2);margin-bottom:8px}
.chart-card svg{width:100%;display:block}
.chart-tooltip{position:absolute;background:var(--border);border:1px solid var(--border2);border-radius:4px;padding:4px 8px;font-size:11px;color:var(--text2);pointer-events:none;white-space:nowrap;display:none;z-index:10}

@media(max-width:900px){
  .charts-row{grid-template-columns:1fr}
}

footer{text-align:center;padding:24px 0;border-top:1px solid var(--border);margin-top:32px;font-size:12px;color:var(--muted2)}
footer a{color:var(--muted2)}
footer a:hover{color:var(--accent)}

@media(max-width:640px){
  .stats-row{grid-template-columns:repeat(2,1fr)}
  .networks table{font-size:12px}
  header{flex-direction:column}
}
</style>
</head>
<body>
<div class="container">

<div class="banner-stack" id="banner-stack" style="display:none"></div>

<header>
  <div>
    <h1>Pilot Protocol</h1>
    <div class="uptime">Uptime: <span id="uptime">—</span></div>
    <div class="token-bar">
      <input type="password" id="token-input" placeholder="Dashboard token" autocomplete="off">
      <button id="token-btn" onclick="toggleToken()">Unlock</button>
      <span class="status" id="token-status"></span>
    </div>
  </div>
  <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" aria-label="Toggle theme" title="Toggle theme">◐</button>
</header>

<div class="stats-row">
  <div class="stat-card">
    <span class="value" id="total-requests">—</span>
    <span class="label">Total Requests</span>
  </div>
  <div class="stat-card">
    <span class="value" id="total-nodes">—</span>
    <span class="label">Total Nodes</span>
  </div>
  <div class="stat-card">
    <span class="value" id="active-nodes">—</span>
    <span class="label">Online Nodes</span>
  </div>
</div>

<div class="system-row">
  <div class="system-card">
    <h2>System Status</h2>
    <div id="services"></div>
  </div>
  <div class="system-card">
    <h2>Live Throughput</h2>
    <div class="pulse-wrap">
      <span class="pulse-val" id="pulse-now">—</span>
      <span class="pulse-unit">req/s</span>
    </div>
    <div class="pulse-strip" id="pulse-strip"></div>
    <div class="pulse-meta"><span>60s window</span><span>peak <span id="pulse-peak">—</span> req/s</span></div>
  </div>
</div>

<div class="charts-row" id="charts-row" style="display:none">
  <div class="chart-card">
    <h2>Online Nodes — Last 24 Hours</h2>
    <div class="disclaimer">Since last registry restart</div>
    <div style="position:relative">
      <svg id="chart-hourly" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-hourly"></div>
    </div>
  </div>
  <div class="chart-card">
    <h2>Online Nodes — Last 7 Days</h2>
    <div class="disclaimer">Since last registry restart</div>
    <div style="position:relative">
      <svg id="chart-weekly" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-weekly"></div>
    </div>
  </div>
</div>


<div class="networks" id="networks">
  <h2>Networks</h2>
  <table>
    <thead><tr><th>Network</th><th>Members</th><th>Online</th><th>Requests</th></tr></thead>
    <tbody id="net-tbody"></tbody>
  </table>
</div>

<footer>
  Pilot Protocol &middot;
  <a href="https://pilotprotocol.network">pilotprotocol.network</a> &middot;
  <a href="https://github.com/TeoSlayer/pilotprotocol">GitHub</a>
</footer>

</div>
<script>
function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function uptimeStr(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');p.push(m+'m');return p.join(' ')}
function fmtDateTime(ms){var d=new Date(ms);var M=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];var pad=function(n){return n<10?'0'+n:''+n};return M[d.getMonth()]+' '+d.getDate()+', '+d.getFullYear()+' '+pad(d.getHours())+':'+pad(d.getMinutes())}
function escapeHtml(s){return String(s||'').replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function renderBanner(b,maint){
  var stack=document.getElementById('banner-stack');
  if(!stack)return;
  var html='';
  if(maint){
    html+='<div class="release-banner maintenance"><span class="rb-dot"></span><span>'+escapeHtml(maint)+'</span></div>';
  }
  if(b&&b.version){
    html+='<div class="release-banner"><span class="rb-dot"></span><span>Update <span class="rb-ver">'+escapeHtml(b.version)+'</span> propagating across network, peers may be unreachable.</span></div>';
  }
  if(!html){stack.style.display='none';stack.innerHTML='';return}
  stack.innerHTML=html;
  stack.style.display='flex';
}
function getToken(){return localStorage.getItem('pilot_dash_token')||''}
function setToken(t){if(t)localStorage.setItem('pilot_dash_token',t);else localStorage.removeItem('pilot_dash_token')}
function toggleToken(){
  var inp=document.getElementById('token-input');
  var btn=document.getElementById('token-btn');
  if(getToken()){setToken('');inp.value='';btn.textContent='Unlock';document.getElementById('token-status').textContent='';document.getElementById('token-status').className='status';document.getElementById('networks').style.display='none';update();return}
  var t=inp.value.trim();if(!t)return;
  setToken(t);btn.textContent='Lock';update();
}
function initToken(){
  var t=getToken();
  if(t){document.getElementById('token-input').value=t;document.getElementById('token-btn').textContent='Lock'}
}
function renderNetworks(networks){
  var wrap=document.getElementById('networks');
  var tbody=document.getElementById('net-tbody');
  if(!networks||!networks.length){wrap.style.display='none';var st=document.getElementById('token-status');if(getToken()){st.textContent='invalid token';st.className='status'}return}
  wrap.style.display='block';
  var st=document.getElementById('token-status');st.textContent='authenticated';st.className='status ok';
  var html='';
  networks.forEach(function(n){
    html+='<tr><td>'+n.name+' <span class="net-id">#'+n.id+'</span></td><td>'+fmt(n.members)+'</td><td>'+fmt(n.online)+'</td><td>'+fmt(n.requests)+'</td></tr>';
  });
  tbody.innerHTML=html;
}
function themeVar(name,fallback){
  var v=getComputedStyle(document.documentElement).getPropertyValue(name);
  return (v&&v.trim())||fallback;
}
function drawChart(svg,tip,samples,valFn,labelFn,color,unit,zoomY){
  if(!svg)return;
  var accent=themeVar('--accent','#58a6ff');
  var good=themeVar('--good','#3fb950');
  var grid=themeVar('--grid','#21262d');
  var muted2=themeVar('--muted2','#484f58');
  var bg=themeVar('--panel','#161b22');
  if(color==='accent')color=accent;
  else if(color==='good')color=good;
  color=color||accent;
  unit=unit||'online';
  if(!samples||!samples.length){svg.innerHTML='';return}
  var vb=(svg.getAttribute('viewBox')||'0 0 400 180').split(/\s+/);
  var W=parseFloat(vb[2])||400,H=parseFloat(vb[3])||180;
  var padL=40,padR=14,padT=10,padB=30;
  var cW=W-padL-padR,cH=H-padT-padB;
  var vals=samples.map(valFn);
  var maxV=Math.max.apply(null,vals);
  var minV=Math.min.apply(null,vals);
  if(maxV===0)maxV=1;
  var gridMin=0,gridMax,step;
  if(zoomY&&maxV>minV){
    var gridSpan=maxV-minV;
    step=Math.pow(10,Math.floor(Math.log10(gridSpan||1)));
    if(gridSpan/step<2)step=step/4;
    else if(gridSpan/step<5)step=step/2;
    gridMin=Math.floor(minV/step)*step;
    gridMax=Math.ceil(maxV/step)*step;
  }else{
    step=Math.pow(10,Math.floor(Math.log10(maxV||1)));
    if(maxV/step<2)step=step/4;
    else if(maxV/step<5)step=step/2;
    gridMax=Math.ceil(maxV/step)*step;
  }
  if(gridMax<=gridMin)gridMax=gridMin+1;
  var range=gridMax-gridMin;
  var html='';
  for(var g=gridMin;g<=gridMax+step*0.001;g+=step){
    var gy=padT+cH-((g-gridMin)/range)*cH;
    html+='<line x1="'+padL+'" y1="'+gy+'" x2="'+(W-padR)+'" y2="'+gy+'" stroke="'+grid+'" stroke-width="1"/>';
    html+='<text x="'+(padL-4)+'" y="'+(gy+4)+'" fill="'+muted2+'" font-size="10" text-anchor="end" font-family="monospace">'+g+'</text>';
  }
  var pts=[];
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-((vals[i]-gridMin)/range)*cH;
    pts.push(x.toFixed(1)+','+y.toFixed(1));
  }
  var polyPts=pts.join(' ');
  var firstX=padL+(vals.length>1?0:0.5)*cW;
  var lastX=padL+(vals.length>1?1:0.5)*cW;
  var areaFill=firstX.toFixed(1)+','+(padT+cH)+' '+polyPts+' '+lastX.toFixed(1)+','+(padT+cH);
  html+='<polygon points="'+areaFill+'" fill="'+color+'" fill-opacity="0.15"/>';
  html+='<polyline points="'+polyPts+'" fill="none" stroke="'+color+'" stroke-width="2"/>';
  var lblStep=Math.max(1,Math.ceil(vals.length/7));
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-((vals[i]-gridMin)/range)*cH;
    html+='<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="3" fill="'+color+'" stroke="'+bg+'" stroke-width="1.5"/>';
    var lbl=labelFn(samples[i]);
    var showLbl=(i%lblStep===0)||(i===vals.length-1);
    if(showLbl){
      var anchor='middle';
      if(i===0)anchor='start';
      else if(i===vals.length-1)anchor='end';
      html+='<text x="'+x.toFixed(1)+'" y="'+(padT+cH+16)+'" fill="'+muted2+'" font-size="9" text-anchor="'+anchor+'" font-family="monospace">'+lbl+'</text>';
    }
    var rw=cW/(vals.length||1);
    html+='<rect x="'+(x-rw/2).toFixed(1)+'" y="'+padT+'" width="'+rw.toFixed(1)+'" height="'+cH+'" fill="transparent" data-val="'+vals[i]+'" data-lbl="'+lbl+'" data-x="'+x.toFixed(1)+'"/>';
  }
  svg.innerHTML=html;
  if(tip){
    svg.querySelectorAll('rect[data-val]').forEach(function(r){
      r.addEventListener('mouseenter',function(){
        tip.textContent=r.getAttribute('data-lbl')+': '+r.getAttribute('data-val')+' '+unit;
        tip.style.display='block';
        var svgRect=svg.getBoundingClientRect();
        var px=parseFloat(r.getAttribute('data-x'))/W*svgRect.width;
        tip.style.left=(px+4)+'px';tip.style.top='0px';
      });
      r.addEventListener('mouseleave',function(){tip.style.display='none'});
    });
  }
}
function renderCharts(hourly,daily){
  var row=document.getElementById('charts-row');
  if((!hourly||!hourly.length)&&(!daily||!daily.length)){row.style.display='none';return}
  row.style.display='grid';
  drawChart(document.getElementById('chart-hourly'),document.getElementById('tip-hourly'),hourly||[],function(s){return s.online_nodes||0},function(s){
    var d=new Date(s.ts*1000);return ('0'+d.getHours()).slice(-2)+':00';
  },'accent','online',true);
  var d7=(daily||[]).slice(-7);
  drawChart(document.getElementById('chart-weekly'),document.getElementById('tip-weekly'),d7,function(s){return s.online_nodes||0},function(s){
    var d=new Date(s.ts*1000);return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()]+' '+d.getDate();
  },'accent','online',true);
}
function update(){
  var url='/api/stats';
  var t=getToken();if(t)url+='?token='+encodeURIComponent(t);
  fetch(url).then(function(r){return r.json()}).then(function(d){
    document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('total-nodes').textContent=fmt(d.total_nodes||0);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes||0);
    document.getElementById('uptime').textContent=uptimeStr(d.uptime_secs);
    renderServices(d.uptime_secs,d.restart_events,d.probes||{});
    renderBanner(d.release_banner,d.maintenance_banner);
    renderCharts(d.hourly,d.daily);
    renderNetworks(d.networks);
  }).catch(function(){})
}
function renderServices(uptimeSecs,restartEvents,probes){
  var el=document.getElementById('services');if(!el)return;
  var services=[
    {key:'registry',name:'Registry'},
    {key:'beacon',name:'Beacon Relay'},
    {key:'dashboard',name:'Dashboard API'},
    {key:'metrics',name:'Metrics'},
  ];
  var now=Date.now();
  var processStart=now-(uptimeSecs||0)*1000;
  var retention=30*86400000;
  var earliestGlobal=processStart;
  (restartEvents||[]).forEach(function(t){if(t<earliestGlobal)earliestGlobal=t});
  if(earliestGlobal<now-retention)earliestGlobal=now-retention;
  var startOfToday=new Date();startOfToday.setHours(0,0,0,0);
  var startToday=startOfToday.getTime();
  var months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  var restartDownMs=5000;
  var restartIntervals=(restartEvents||[]).map(function(t){return [t-restartDownMs/2,t+restartDownMs/2]});
  function computeDays(ps){
    var intervals=((ps&&ps.downtime_intervals)||[]).concat(restartIntervals);
    if(ps&&ps.current_down_start>0){
      intervals=intervals.concat([[ps.current_down_start,now]]);
    }
    var earliest=earliestGlobal;
    if(ps&&ps.last_success>0&&ps.last_success<earliest)earliest=ps.last_success;
    var days=[],totalDownMs=0,totalCoverMs=0;
    for(var d=29;d>=0;d--){
      var dayStart=startToday-d*86400000;
      var dayEnd=dayStart+86400000;
      var coverStart=Math.max(dayStart,earliest);
      var coverEnd=Math.min(dayEnd,now);
      var coverMs=Math.max(0,coverEnd-coverStart);
      if(coverMs<=0){
        days.push({dayStart:dayStart,state:'inactive',upPct:null,downMs:0,coverMs:0,restarts:0});
        continue;
      }
      var downMs=0;
      intervals.forEach(function(iv){
        if(!iv||iv.length!==2)return;
        var a=Math.max(coverStart,iv[0]);
        var b=Math.min(coverEnd,iv[1]);
        if(b>a)downMs+=(b-a);
      });
      if(downMs>coverMs)downMs=coverMs;
      var upPct=(coverMs-downMs)/coverMs*100;
      var restartsOnDay=0;
      (restartEvents||[]).forEach(function(t){if(t>=dayStart&&t<dayEnd)restartsOnDay++});
      var state='ok';
      if(upPct<95)state='down';
      else if(upPct<100||restartsOnDay>0)state='partial';
      days.push({dayStart:dayStart,state:state,upPct:upPct,downMs:downMs,coverMs:coverMs,restarts:restartsOnDay});
      totalDownMs+=downMs;totalCoverMs+=coverMs;
    }
    var pct=totalCoverMs>0?((totalCoverMs-totalDownMs)/totalCoverMs*100):100;
    return {days:days,pct:pct};
  }
  var html='';
  services.forEach(function(svc){
    var ps=(probes&&probes[svc.key])||null;
    var r=computeDays(ps);
    var bars='';
    r.days.forEach(function(day){
      var cls=day.state==='ok'?'':day.state;
      var dt=new Date(day.dayStart);
      var dateStr=months[dt.getMonth()]+' '+dt.getDate();
      var tip='';
      if(day.state==='inactive'){
        tip='<div class="v">'+dateStr+'</div><div>no data</div>';
      }else{
        tip='<div class="v">'+dateStr+'</div><div>uptime: <span class="v">'+day.upPct.toFixed(2)+'%</span></div>';
        if(day.downMs>0)tip+='<div>downtime: <span class="v">'+fmtDur(day.downMs)+'</span></div>';
        if(day.restarts>0)tip+='<div>restarts: <span class="v">'+day.restarts+'</span></div>';
      }
      bars+='<span class="svc-bar-wrap"><span class="svc-bar '+cls+'"></span><span class="svc-bar-tip">'+tip+'</span></span>';
    });
    var live=ps&&ps.current_down_start>0?'down':'ok';
    html+='<div class="svc-row">'+
      '<span class="svc-name"><span class="svc-dot '+(live!=='ok'?live:'')+'"></span>'+svc.name+'</span>'+
      '<div class="svc-bars">'+bars+'</div>'+
      '<span class="svc-uptime">'+r.pct.toFixed(2)+'%</span>'+
      '</div>';
  });
  el.innerHTML=html;
}
function fmtDur(ms){
  if(ms<60000)return Math.round(ms/1000)+'s';
  if(ms<3600000)return Math.round(ms/60000)+'m';
  if(ms<86400000)return (ms/3600000).toFixed(1)+'h';
  return (ms/86400000).toFixed(1)+'d';
}
var _pulseSamples=[];
var _pulsePeak=0;
function renderPulse(){
  var strip=document.getElementById('pulse-strip');if(!strip)return;
  var N=60;
  while(_pulseSamples.length>N)_pulseSamples.shift();
  var rates=[];
  for(var i=1;i<_pulseSamples.length;i++){
    var dt=(_pulseSamples[i].ts-_pulseSamples[i-1].ts)/1000;
    var dr=_pulseSamples[i].total-_pulseSamples[i-1].total;
    if(dt>0&&dr>=0)rates.push(dr/dt);
  }
  var maxR=Math.max.apply(null,rates.concat([1]));
  if(maxR>_pulsePeak)_pulsePeak=maxR;
  var html='';
  for(var i=0;i<N;i++){
    var idx=rates.length-N+i;
    if(idx<0){html+='<div class="pulse-bar" style="height:1px"></div>';continue}
    var h=Math.max(1,(rates[idx]/maxR)*40);
    var live=(i===N-1)?' live':'';
    html+='<div class="pulse-bar'+live+'" style="height:'+h.toFixed(1)+'px"></div>';
  }
  strip.innerHTML=html;
  var now=rates.length?rates[rates.length-1]:0;
  document.getElementById('pulse-now').textContent=fmt(Math.round(now));
  document.getElementById('pulse-peak').textContent=fmt(Math.round(_pulsePeak));
}
function pulseTick(){
  fetch('/api/pulse').then(function(r){return r.json()}).then(function(d){
    if(d.samples&&d.samples.length){
      _pulseSamples=d.samples.map(function(s){return {ts:s.ts,total:s.total}});
    }else{
      _pulseSamples.push({ts:d.ts,total:d.total_requests});
    }
    renderPulse();
  }).catch(function(){});
}
function applyTheme(t){
  if(t==='light')document.documentElement.setAttribute('data-theme','light');
  else document.documentElement.removeAttribute('data-theme');
  var btn=document.getElementById('theme-toggle');
  if(btn)btn.textContent=(t==='light')?'◑':'◐';
}
function currentTheme(){
  var stored=localStorage.getItem('pilot_dash_theme');
  if(stored==='light'||stored==='dark')return stored;
  return (window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';
}
function toggleTheme(){
  var next=(currentTheme()==='light')?'dark':'light';
  localStorage.setItem('pilot_dash_theme',next);
  applyTheme(next);
  update();
}
applyTheme(currentTheme());
if(window.matchMedia){
  var mq=window.matchMedia('(prefers-color-scheme: light)');
  var sysListener=function(){if(!localStorage.getItem('pilot_dash_theme')){applyTheme(currentTheme());update();}};
  if(mq.addEventListener)mq.addEventListener('change',sysListener);
  else if(mq.addListener)mq.addListener(sysListener);
}
initToken();update();setInterval(update,30000);
pulseTick();setInterval(pulseTick,2000);
</script>
</body>
</html>`
