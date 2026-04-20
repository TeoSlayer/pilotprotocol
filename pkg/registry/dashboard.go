package registry

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

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
		var stats DashboardStats
		if token := r.URL.Query().Get("token"); token != "" {
			s.mu.RLock()
			dt := s.dashboardToken
			s.mu.RUnlock()
			if dt != "" && subtle.ConstantTimeCompare([]byte(token), []byte(dt)) == 1 {
				stats = s.GetDashboardStatsExtended()
			} else {
				stats = s.GetDashboardStatsWithHistory()
			}
		} else {
			stats = s.GetDashboardStatsWithHistory()
		}
		_ = json.NewEncoder(w).Encode(stats)
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
		onlineThreshold := now.Add(-staleNodeThreshold)
		s.mu.RLock()
		online := 0
		for _, node := range s.nodes {
			if node.LastSeen.After(onlineThreshold) {
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

	mux.HandleFunc("/api/badge/trust", func(w http.ResponseWriter, r *http.Request) {
		stats := s.GetDashboardStats()
		c := "#58a6ff"
		if stats.TotalTrustLinks == 0 {
			c = "#9f9f9f"
		}
		serveBadge(w, "trust links", fmtCount(stats.TotalTrustLinks), c)
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
.theme-toggle{background:var(--panel);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:6px 10px;font-family:inherit;font-size:12px;cursor:pointer;line-height:1}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}

.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:var(--text2);display:block}
.stat-card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}

.versions{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:32px}
.versions h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.ver-row{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.ver-label{min-width:120px;font-size:13px;color:var(--text)}
.ver-bar-bg{flex:1;height:20px;background:var(--panel2);border-radius:4px;overflow:hidden;border:1px solid var(--border)}
.ver-bar{height:100%;border-radius:4px;transition:width 0.3s}
.ver-count{min-width:60px;text-align:right;font-size:13px;color:var(--muted)}

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
.networks tr{cursor:pointer}
.networks tr.active td{background:var(--panel2)}

.net-detail{background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-top:12px;display:none}
.net-detail h3{font-size:14px;font-weight:600;color:var(--text2);margin-bottom:4px}
.net-detail .disclaimer{font-size:11px;color:var(--muted2);margin-bottom:12px}
.net-detail .net-charts{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.net-detail .net-chart-wrap{position:relative}
.net-detail .net-chart-label{font-size:12px;color:var(--muted);margin-bottom:6px}
.net-detail svg{width:100%;display:block}

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
.svc-bar{flex:1;background:var(--good);border-radius:1px;opacity:0.85;transition:opacity 0.2s}
.svc-bar:hover{opacity:1}
.svc-bar.unknown{background:var(--border2);opacity:0.4}
.svc-bar.degraded{background:#f59e0b}
.svc-bar.down{background:#ef4444}
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

.movers{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:32px;display:none}
.movers h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px}
.movers-sub{font-size:11px;color:var(--muted2);margin-bottom:12px}
.mover-row{display:grid;grid-template-columns:24px 1fr auto auto;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)}
.mover-row:last-child{border-bottom:none}
.mover-arrow{font-size:16px;line-height:1;text-align:center}
.mover-arrow.up{color:var(--good)}
.mover-arrow.down{color:#ef4444}
.mover-name{font-size:14px;color:var(--text)}
.mover-net-id{font-size:11px;color:var(--muted);margin-left:6px}
.mover-delta{font-size:14px;font-weight:600;font-variant-numeric:tabular-nums;min-width:80px;text-align:right}
.mover-delta.up{color:var(--good)}
.mover-delta.down{color:#ef4444}
.mover-rate{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums;min-width:90px;text-align:right}

.charts-row{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:32px}
.chart-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px}
.chart-card h2{font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.chart-card .disclaimer{font-size:11px;color:var(--muted2);margin-bottom:8px}
.chart-card svg{width:100%;display:block}
.chart-tooltip{position:absolute;background:var(--border);border:1px solid var(--border2);border-radius:4px;padding:4px 8px;font-size:11px;color:var(--text2);pointer-events:none;white-space:nowrap;display:none;z-index:10}

@media(max-width:640px){
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
      <svg id="chart-daily" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-daily"></div>
    </div>
  </div>
</div>

<div class="versions" id="versions"></div>

<div class="movers" id="movers">
  <h2>Top Movers — Last Hour</h2>
  <div class="movers-sub">Change in request rate vs previous hour</div>
  <div id="movers-list"></div>
</div>

<div class="networks" id="networks">
  <h2>Networks</h2>
  <table>
    <thead><tr><th>Network</th><th>Members</th><th>Online</th><th>Requests</th></tr></thead>
    <tbody id="net-tbody"></tbody>
  </table>
  <div class="net-detail" id="net-detail">
    <h3 id="net-detail-title"></h3>
    <div class="disclaimer">Since last registry restart</div>
    <div class="net-charts">
      <div class="net-chart-wrap">
        <div class="net-chart-label">Online Members — Last 24 Hours</div>
        <div style="position:relative">
          <svg id="net-chart-hourly" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
          <div class="chart-tooltip" id="net-tip-hourly"></div>
        </div>
      </div>
      <div class="net-chart-wrap">
        <div class="net-chart-label">Online Members — Last 7 Days</div>
        <div style="position:relative">
          <svg id="net-chart-daily" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
          <div class="chart-tooltip" id="net-tip-daily"></div>
        </div>
      </div>
    </div>
  </div>
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
function renderVersions(versions){
  var el=document.getElementById('versions');
  if(!versions||!Object.keys(versions).length){el.innerHTML='';return}
  var sorted=Object.entries(versions).sort(function(a,b){return b[1]-a[1]});
  var max=sorted[0][1];
  var colors=['#58a6ff','#3fb950','#a855f7','#f59e0b','#f97316','#ef4444','#8b949e'];
  var html='<h2>Client Versions</h2>';
  sorted.forEach(function(e,i){
    var pct=Math.max(2,Math.round(e[1]/max*100));
    var c=colors[i%colors.length];
    html+='<div class="ver-row"><span class="ver-label">'+e[0]+'</span><div class="ver-bar-bg"><div class="ver-bar" style="width:'+pct+'%;background:'+c+'"></div></div><span class="ver-count">'+fmt(e[1])+'</span></div>';
  });
  el.innerHTML=html;
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
var _netData=[];
var _selectedNet=-1;
function renderNetworks(networks){
  var wrap=document.getElementById('networks');
  var tbody=document.getElementById('net-tbody');
  if(!networks||!networks.length){wrap.style.display='none';document.getElementById('net-detail').style.display='none';var st=document.getElementById('token-status');if(getToken()){st.textContent='invalid token';st.className='status'}return}
  wrap.style.display='block';
  _netData=networks;
  var st=document.getElementById('token-status');st.textContent='authenticated';st.className='status ok';
  var html='';
  networks.forEach(function(n,i){
    var cls=n.id===_selectedNet?' class="active"':'';
    html+='<tr'+cls+' data-idx="'+i+'" onclick="showNetDetail('+i+')"><td>'+n.name+' <span class="net-id">#'+n.id+'</span></td><td>'+fmt(n.members)+'</td><td>'+fmt(n.online)+'</td><td>'+fmt(n.requests)+'</td></tr>';
  });
  tbody.innerHTML=html;
  if(_selectedNet>=0){
    var found=false;
    for(var i=0;i<networks.length;i++){if(networks[i].id===_selectedNet){showNetDetail(i);found=true;break}}
    if(!found)document.getElementById('net-detail').style.display='none';
  }
}
function showNetDetail(idx){
  var n=_netData[idx];if(!n)return;
  _selectedNet=n.id;
  var rows=document.getElementById('net-tbody').querySelectorAll('tr');
  rows.forEach(function(r){r.classList.remove('active')});
  rows[idx].classList.add('active');
  document.getElementById('net-detail-title').textContent=n.name+' (#'+n.id+')';
  var panel=document.getElementById('net-detail');
  panel.style.display='block';
  var hourly=n.hourly||[];
  var daily=n.daily||[];
  if(!hourly.length&&!daily.length){
    document.getElementById('net-chart-hourly').innerHTML='<text x="200" y="90" fill="#484f58" font-size="12" text-anchor="middle" font-family="monospace">No history yet</text>';
    document.getElementById('net-chart-daily').innerHTML='<text x="200" y="90" fill="#484f58" font-size="12" text-anchor="middle" font-family="monospace">No history yet</text>';
    return;
  }
  drawChart(document.getElementById('net-chart-hourly'),document.getElementById('net-tip-hourly'),hourly,function(s){return s.online||0},function(s){
    var d=new Date(s.ts*1000);return ('0'+d.getHours()).slice(-2)+':00';
  },'good');
  drawChart(document.getElementById('net-chart-daily'),document.getElementById('net-tip-daily'),daily,function(s){return s.online||0},function(s){
    var d=new Date(s.ts*1000);return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()]+' '+d.getDate();
  },'good');
}
function themeVar(name,fallback){
  var v=getComputedStyle(document.documentElement).getPropertyValue(name);
  return (v&&v.trim())||fallback;
}
function drawChart(svg,tip,samples,valFn,labelFn,color,unit){
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
  var W=400,H=180,padL=40,padR=14,padT=10,padB=30;
  var cW=W-padL-padR,cH=H-padT-padB;
  var vals=samples.map(valFn);
  var maxV=Math.max.apply(null,vals);
  if(maxV===0)maxV=1;
  var step=Math.pow(10,Math.floor(Math.log10(maxV||1)));
  if(maxV/step<2)step=step/4;
  else if(maxV/step<5)step=step/2;
  var gridMax=Math.ceil(maxV/step)*step;
  if(gridMax===0)gridMax=1;
  var html='';
  for(var g=0;g<=gridMax;g+=step){
    var gy=padT+cH-(g/gridMax)*cH;
    html+='<line x1="'+padL+'" y1="'+gy+'" x2="'+(W-padR)+'" y2="'+gy+'" stroke="'+grid+'" stroke-width="1"/>';
    html+='<text x="'+(padL-4)+'" y="'+(gy+4)+'" fill="'+muted2+'" font-size="10" text-anchor="end" font-family="monospace">'+g+'</text>';
  }
  var pts=[];
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-(vals[i]/gridMax)*cH;
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
    var y=padT+cH-(vals[i]/gridMax)*cH;
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
  },'accent','online');
  drawChart(document.getElementById('chart-daily'),document.getElementById('tip-daily'),daily||[],function(s){return s.online_nodes||0},function(s){
    var d=new Date(s.ts*1000);return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()]+' '+d.getDate();
  },'accent','online');
}
function update(){
  var url='/api/stats';
  var t=getToken();if(t)url+='?token='+encodeURIComponent(t);
  fetch(url).then(function(r){return r.json()}).then(function(d){
    document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('total-nodes').textContent=fmt(d.total_nodes||0);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes||0);
    document.getElementById('uptime').textContent=uptimeStr(d.uptime_secs);
    renderServices(d.uptime_secs);
    renderVersions(d.versions);
    renderCharts(d.hourly,d.daily);
    renderMovers(d.networks);
    renderNetworks(d.networks);
  }).catch(function(){})
}
function renderMovers(networks){
  var el=document.getElementById('movers');
  if(!networks||!networks.length){el.style.display='none';return}
  var cands=[];
  networks.forEach(function(n){
    var h=n.hourly;if(!h||h.length<3)return;
    var i3=h.length-1,i2=h.length-2,i1=h.length-3;
    var dtLast=h[i3].ts-h[i2].ts;
    var dtPrev=h[i2].ts-h[i1].ts;
    if(dtLast<=0||dtPrev<=0)return;
    var rateLast=(h[i3].requests-h[i2].requests)/dtLast;
    var ratePrev=(h[i2].requests-h[i1].requests)/dtPrev;
    if(rateLast<0||ratePrev<0)return;
    if(rateLast<1&&ratePrev<1)return;
    var pct=ratePrev>0?((rateLast-ratePrev)/ratePrev)*100:(rateLast>0?100:0);
    cands.push({n:n,rateLast:rateLast,pct:pct});
  });
  if(!cands.length){el.style.display='none';return}
  cands.sort(function(a,b){return Math.abs(b.pct)-Math.abs(a.pct)});
  var top=cands.slice(0,3);
  var html='';
  top.forEach(function(m){
    var dir=m.pct>=0?'up':'down';
    var arrow=m.pct>=0?'▲':'▼';
    var sign=m.pct>=0?'+':'';
    html+='<div class="mover-row">'+
      '<span class="mover-arrow '+dir+'">'+arrow+'</span>'+
      '<span class="mover-name">'+m.n.name+'<span class="mover-net-id">#'+m.n.id+'</span></span>'+
      '<span class="mover-delta '+dir+'">'+sign+m.pct.toFixed(1)+'%</span>'+
      '<span class="mover-rate">'+fmt(Math.round(m.rateLast))+' r/s</span>'+
      '</div>';
  });
  document.getElementById('movers-list').innerHTML=html;
  el.style.display='block';
}
function renderServices(uptimeSecs){
  var el=document.getElementById('services');if(!el)return;
  var activeDays=Math.min(90,Math.floor((uptimeSecs||0)/86400));
  var services=[
    {name:'Registry',status:'ok'},
    {name:'Beacon Relay',status:'ok'},
    {name:'Dashboard API',status:'ok'},
    {name:'Metrics',status:'ok'},
  ];
  var uptimePct=(uptimeSecs>0)?(100).toFixed(2):0;
  var html='';
  services.forEach(function(svc){
    var bars='';
    for(var i=0;i<90;i++){
      var fromNow=89-i;
      var cls=(fromNow<activeDays)?'':'unknown';
      bars+='<div class="svc-bar '+cls+'" title="'+fromNow+'d ago"></div>';
    }
    html+='<div class="svc-row">'+
      '<span class="svc-name"><span class="svc-dot '+(svc.status!=='ok'?svc.status:'')+'"></span>'+svc.name+'</span>'+
      '<div class="svc-bars">'+bars+'</div>'+
      '<span class="svc-uptime">'+uptimePct+'%</span>'+
      '</div>';
  });
  el.innerHTML=html;
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

// pulseSample is one entry in the server-side 1/sec request-count ring.
type pulseSample struct {
	Ts    int64 `json:"ts"`
	Total int64 `json:"total"`
}

func (s *Server) pulseLoop() {
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
