// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

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
	"strings"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// readSmallBody reads up to maxBytes of the request body and trims trailing
// whitespace. Used by admin write endpoints whose payloads are short text.
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

// ServeDashboard starts an HTTP server serving the dashboard UI and stats API.
func (s *Server) ServeDashboard(addr string) error {
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
			s.mu.RLock()
			dt := s.dashboardToken
			s.mu.RUnlock()
			if dt != "" && subtle.ConstantTimeCompare([]byte(token), []byte(dt)) == 1 {
				authenticated = true
			}
		}
		_ = json.NewEncoder(w).Encode(s.buildDashboardResponse(authenticated))
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
		s.mu.RLock()
		nodes := make([]map[string]interface{}, 0, len(s.nodes))
		for _, node := range s.nodes {
			entry := map[string]interface{}{
				"node_id": node.ID,
				"address": protocol.Addr{Network: 0, Node: node.ID}.String(),
			}
			if node.Hostname != "" {
				entry["hostname"] = node.Hostname
			}
			entry["last_seen"] = node.getLastSeen().Format(time.RFC3339)
			nodes = append(nodes, entry)
		}
		s.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"nodes": nodes,
			"count": len(nodes),
		})
	})

	// /api/banner — admin-only management endpoint for the dashboard
	// notice. Both GET and PUT require the admin token (header
	// `X-Admin-Token` or query `?admin_token=`); the public can still
	// read the rendered banner via `/api/stats.maintenance_banner` and
	// the dashboard HTML — this endpoint is for operator tooling only.
	// PUT body is the new banner text (empty string clears it).
	mux.HandleFunc("/api/banner", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Admin-Token")
		if token == "" {
			token = r.URL.Query().Get("admin_token")
		}
		s.mu.RLock()
		adminToken := s.adminToken
		s.mu.RUnlock()
		if adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"banner": s.MaintenanceBanner(),
			})
		case http.MethodPut, http.MethodPost:
			body, err := readSmallBody(r, 8192)
			if err != nil {
				http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
				return
			}
			s.SetMaintenanceBanner(body)
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
			"total_requests": s.requestCount.Load(),
			"samples":        s.GetPulseSamples(),
		})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		nodeCount := len(s.nodes)
		startTime := s.startTime
		s.mu.RUnlock()

		now := time.Now()
		onlineThreshold := now.Add(-s.StaleNodeThreshold())
		s.mu.RLock()
		online := 0
		for _, node := range s.nodes {
			// Atomic-aware: heartbeat hot path only updates lastSeenNano.
			if node.getLastSeen().After(onlineThreshold) {
				online++
			}
		}
		s.mu.RUnlock()

		healthy := nodeCount >= 0 // registry is healthy if running
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
		stats := s.GetDashboardStats()
		c := "#4c1"
		if stats.ActiveNodes == 0 {
			c = "#9f9f9f"
		}
		serveBadge(w, "online nodes", fmtCount(stats.ActiveNodes), c)
	})

	mux.HandleFunc("/api/badge/requests", func(w http.ResponseWriter, r *http.Request) {
		stats := s.GetDashboardStats()
		serveBadge(w, "requests", fmtCount(int(stats.TotalRequests)), "#a855f7")
	})

	// Snapshot trigger endpoint (POST only, localhost only)
	mux.HandleFunc("/api/snapshot", func(w http.ResponseWriter, r *http.Request) {
		// Check localhost - only trust X-Real-IP if request is from a trusted proxy
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		clientIP := remoteIP

		// Only trust X-Real-IP header if the request is already from localhost (trusted proxy)
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
		if err := s.TriggerSnapshot(); err != nil {
			http.Error(w, fmt.Sprintf("snapshot failed: %v", err), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"message": "snapshot saved successfully",
		})
	})

	// localhostOnly rejects requests not originating from loopback.
	// Only trusts X-Real-IP header when the request is from a trusted proxy (localhost).
	localhostOnly := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Get the actual remote address
			remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			clientIP := remoteIP

			// Only trust X-Real-IP header if the request is already from localhost (trusted proxy)
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

	// Prometheus metrics endpoint (localhost only — scraped by Alloy on the same host)
	mux.HandleFunc("/metrics", localhostOnly(func(w http.ResponseWriter, r *http.Request) {
		s.metrics.updateGauges(s)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.metrics.WriteTo(w)
	}))

	// pprof endpoints for live profiling (localhost only)
	mux.HandleFunc("/debug/pprof/", localhostOnly(pprof.Index))
	mux.HandleFunc("/debug/pprof/cmdline", localhostOnly(pprof.Cmdline))
	mux.HandleFunc("/debug/pprof/profile", localhostOnly(pprof.Profile))
	mux.HandleFunc("/debug/pprof/symbol", localhostOnly(pprof.Symbol))
	mux.HandleFunc("/debug/pprof/trace", localhostOnly(pprof.Trace))

	slog.Info("dashboard listening", "addr", addr)
	return http.ListenAndServe(addr, mux)
}

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

// dashboardResponse is the JSON payload served by /api/stats. It exposes only
// the fields the dashboard UI actually renders — top counters, the online-nodes
// curve, system-status probes, and (when authenticated) the per-network table.
// Internal series like full StatsSample/NetworkSampleEntry history, version
// distribution, relay counters, and req/day deltas are never serialized here.
type dashboardResponse struct {
	TotalRequests     int64                  `json:"total_requests"`
	TotalNodes        int                    `json:"total_nodes"`
	ActiveNodes       int                    `json:"active_nodes"`
	UptimeSecs        int64                  `json:"uptime_secs"`
	RestartEvents     []int64                `json:"restart_events,omitempty"`
	Probes            map[string]*ProbeState `json:"probes,omitempty"`
	ReleaseBanner     *ReleaseBanner         `json:"release_banner,omitempty"`
	MaintenanceBanner string                 `json:"maintenance_banner,omitempty"`
	Hourly            []dashboardSample      `json:"hourly,omitempty"`
	Daily             []dashboardSample      `json:"daily,omitempty"`
	Networks          []dashboardNetwork     `json:"networks,omitempty"`
}

// dashboardSample carries the single curve plotted by the chart: the online-nodes
// count at a point in time. Total requests / total nodes / trust links from the
// underlying StatsSample are intentionally omitted.
type dashboardSample struct {
	Ts          int64 `json:"ts"`
	OnlineNodes int   `json:"online_nodes"`
}

// dashboardNetwork mirrors the columns of the dashboard's networks table.
// Per-network hourly/daily history rings are not exposed here.
type dashboardNetwork struct {
	ID       uint16 `json:"id"`
	Name     string `json:"name"`
	Members  int    `json:"members"`
	Online   int    `json:"online"`
	Requests int64  `json:"requests"`
}

// buildDashboardResponse assembles the slim /api/stats payload. Authenticated
// callers additionally receive the per-network table; everyone gets the chart
// curve (online_nodes only) plus the system-status probe history needed to
// render the 30-day uptime bars.
func (s *Server) buildDashboardResponse(authenticated bool) dashboardResponse {
	var src DashboardStats
	if authenticated {
		src = s.GetDashboardStatsExtended()
	} else {
		src = s.GetDashboardStatsWithHistory()
	}
	out := dashboardResponse{
		TotalRequests:     src.TotalRequests,
		TotalNodes:        src.TotalNodes,
		ActiveNodes:       src.ActiveNodes,
		UptimeSecs:        src.UptimeSecs,
		RestartEvents:     src.RestartEvents,
		Probes:            src.Probes,
		ReleaseBanner:     src.ReleaseBanner,
		MaintenanceBanner: s.MaintenanceBanner(),
	}
	if len(src.Hourly) > 0 {
		out.Hourly = make([]dashboardSample, len(src.Hourly))
		for i, sample := range src.Hourly {
			out.Hourly[i] = dashboardSample{Ts: sample.Timestamp, OnlineNodes: sample.OnlineNodes}
		}
	}
	if len(src.Daily) > 0 {
		out.Daily = make([]dashboardSample, len(src.Daily))
		for i, sample := range src.Daily {
			out.Daily[i] = dashboardSample{Ts: sample.Timestamp, OnlineNodes: sample.OnlineNodes}
		}
	}
	if authenticated && len(src.Networks) > 0 {
		out.Networks = make([]dashboardNetwork, len(src.Networks))
		for i, n := range src.Networks {
			out.Networks[i] = dashboardNetwork{
				ID:       n.ID,
				Name:     n.Name,
				Members:  n.Members,
				Online:   n.Online,
				Requests: n.Requests,
			}
		}
	}
	return out
}

// pulseSample is one entry in the server-side 1/sec request-count ring.
type pulseSample struct {
	Ts    int64 `json:"ts"`
	Total int64 `json:"total"`
}

func (s *Server) pulseLoop() {
	defer recoverHandler("pulseLoop", nil)
	<-s.readyCh
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			sample := pulseSample{Ts: time.Now().UnixMilli(), Total: s.requestCount.Load()}
			s.pulseMu.Lock()
			s.pulseSamples[s.pulseIdx] = sample
			s.pulseIdx++
			if s.pulseIdx >= len(s.pulseSamples) {
				s.pulseIdx = 0
				s.pulseFilled = true
			}
			s.pulseMu.Unlock()
		case <-s.done:
			return
		}
	}
}

// ProbeState holds the health history for a single named probe.
type ProbeState struct {
	LastSuccess       int64      `json:"last_success,omitempty"`       // millis
	DowntimeIntervals [][2]int64 `json:"downtime_intervals,omitempty"` // pruned to 30d
	CurrentDownStart  int64      `json:"current_down_start,omitempty"` // 0 when up
}

// SetDashboardHTTPAddr records the dashboard HTTP listen address so the probe
// loop knows where to dial for the dashboard + metrics probes.
func (s *Server) SetDashboardHTTPAddr(addr string) {
	s.probeMu.Lock()
	s.httpProbeAddr = addr
	s.probeMu.Unlock()
}

var probeNames = []string{"registry", "beacon", "dashboard", "metrics"}

const probeRetention = 30 * 24 * time.Hour

func (s *Server) runProbe(name string, ok bool) {
	now := time.Now().UnixMilli()
	cutoff := time.Now().Add(-probeRetention).UnixMilli()
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if s.probeStates == nil {
		s.probeStates = map[string]*ProbeState{}
	}
	p := s.probeStates[name]
	if p == nil {
		p = &ProbeState{}
		s.probeStates[name] = p
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

func (s *Server) probeRegistry() bool {
	if s.listener == nil {
		return false
	}
	addr := s.listener.Addr().String()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (s *Server) probeBeacon() bool {
	if s.beaconAddr == "" {
		return false
	}
	target, err := net.ResolveUDPAddr("udp", s.beaconAddr)
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

func (s *Server) probeHTTP(path string) bool {
	s.probeMu.Lock()
	addr := s.httpProbeAddr
	s.probeMu.Unlock()
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

// probeLoop runs the 4 component probes at a steady cadence. Each probe records
// its own success/failure into probeStates; downtime intervals are persisted in
// the snapshot so restarts carry history forward.
func (s *Server) probeLoop() {
	defer recoverHandler("probeLoop", nil)
	<-s.readyCh
	// Give listeners a moment to bind before first probe.
	time.Sleep(500 * time.Millisecond)
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	tick := func() {
		s.runProbe("registry", s.probeRegistry())
		s.runProbe("beacon", s.probeBeacon())
		s.runProbe("dashboard", s.probeHTTP("/healthz"))
		s.runProbe("metrics", s.probeHTTP("/metrics"))
		s.save()
	}
	tick()
	for {
		select {
		case <-t.C:
			tick()
		case <-s.done:
			return
		}
	}
}

// heartbeatLoop persists a "last alive" timestamp at a steady cadence so that,
// after a crash or restart, the gap between the last persisted heartbeat and
// the new process start can be recorded as a real downtime interval.
func (s *Server) heartbeatLoop() {
	defer recoverHandler("heartbeatLoop", nil)
	<-s.readyCh
	// Initial tick so a fresh process immediately has a baseline.
	s.lastHeartbeatMs.Store(time.Now().UnixMilli())
	s.save()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.lastHeartbeatMs.Store(time.Now().UnixMilli())
			s.save()
		case <-s.done:
			s.lastHeartbeatMs.Store(time.Now().UnixMilli())
			return
		}
	}
}

func (s *Server) GetPulseSamples() []pulseSample {
	s.pulseMu.Lock()
	defer s.pulseMu.Unlock()
	n := len(s.pulseSamples)
	if !s.pulseFilled {
		out := make([]pulseSample, s.pulseIdx)
		copy(out, s.pulseSamples[:s.pulseIdx])
		return out
	}
	out := make([]pulseSample, 0, n)
	out = append(out, s.pulseSamples[s.pulseIdx:]...)
	out = append(out, s.pulseSamples[:s.pulseIdx]...)
	return out
}
