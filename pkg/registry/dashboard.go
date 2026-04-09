package registry

import (
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
		stats := s.GetDashboardStats()
		_ = json.NewEncoder(w).Encode(stats)
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
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e17;color:#c9d1d9;font-family:'SF Mono','Fira Code','Cascadia Code',monospace;font-size:14px;line-height:1.6}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}

.container{max-width:960px;margin:0 auto;padding:24px 16px}

header{padding:16px 0;border-bottom:1px solid #21262d;margin-bottom:32px}
header h1{font-size:20px;font-weight:600;color:#e6edf3}
.uptime{font-size:12px;color:#8b949e;margin-top:4px}

.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:#e6edf3;display:block}
.stat-card .label{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}

.versions{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px}
.versions h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.ver-row{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.ver-label{min-width:120px;font-size:13px;color:#c9d1d9}
.ver-bar-bg{flex:1;height:20px;background:#0d1117;border-radius:4px;overflow:hidden}
.ver-bar{height:100%;border-radius:4px;transition:width 0.3s}
.ver-count{min-width:60px;text-align:right;font-size:13px;color:#8b949e}

footer{text-align:center;padding:24px 0;border-top:1px solid #21262d;margin-top:32px;font-size:12px;color:#484f58}
footer a{color:#484f58}
footer a:hover{color:#58a6ff}

@media(max-width:640px){
  .stats-row{grid-template-columns:repeat(2,1fr)}
}
</style>
</head>
<body>
<div class="container">

<header>
  <div>
    <h1>Pilot Protocol</h1>
    <div class="uptime">Uptime: <span id="uptime">—</span></div>
  </div>
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
  <div class="stat-card">
    <span class="value" id="trust-links">—</span>
    <span class="label">Trust Links</span>
  </div>
</div>

<div class="versions" id="versions"></div>

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
function update(){
  fetch('/api/stats').then(function(r){return r.json()}).then(function(d){
    document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('total-nodes').textContent=fmt(d.total_nodes||0);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes||0);
    document.getElementById('trust-links').textContent=fmt(d.total_trust_links||0);
    document.getElementById('uptime').textContent=uptimeStr(d.uptime_secs);
    renderVersions(d.versions);
  }).catch(function(){})
}
update();setInterval(update,30000);
</script>
</body>
</html>`
