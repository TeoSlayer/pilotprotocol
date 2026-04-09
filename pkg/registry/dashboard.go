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

.versions{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:32px}
.versions h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.ver-row{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.ver-label{min-width:120px;font-size:13px;color:#c9d1d9}
.ver-bar-bg{flex:1;height:20px;background:#0d1117;border-radius:4px;overflow:hidden}
.ver-bar{height:100%;border-radius:4px;transition:width 0.3s}
.ver-count{min-width:60px;text-align:right;font-size:13px;color:#8b949e}

.token-bar{display:flex;align-items:center;gap:8px;margin-top:8px}
.token-bar input{background:#0d1117;border:1px solid #21262d;border-radius:4px;color:#c9d1d9;padding:4px 8px;font-family:inherit;font-size:12px;width:180px}
.token-bar input::placeholder{color:#484f58}
.token-bar button{background:#21262d;border:1px solid #30363d;border-radius:4px;color:#c9d1d9;padding:4px 10px;font-family:inherit;font-size:12px;cursor:pointer}
.token-bar button:hover{border-color:#58a6ff;color:#58a6ff}
.token-bar .status{font-size:11px;color:#484f58}
.token-bar .status.ok{color:#3fb950}

.networks{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:32px;display:none}
.networks h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.networks table{width:100%;border-collapse:collapse}
.networks th{text-align:left;font-size:11px;color:#484f58;text-transform:uppercase;letter-spacing:0.5px;padding:6px 8px;border-bottom:1px solid #21262d}
.networks td{font-size:13px;color:#c9d1d9;padding:6px 8px;border-bottom:1px solid #161b22}
.networks tr:hover td{background:#0d1117}
.net-id{color:#8b949e;font-size:11px}

.charts-row{display:grid;grid-template-columns:repeat(2,1fr);gap:16px;margin-bottom:32px}
.chart-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px}
.chart-card h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px}
.chart-card .disclaimer{font-size:11px;color:#484f58;margin-bottom:8px}
.chart-card svg{width:100%;display:block}
.chart-tooltip{position:absolute;background:#21262d;border:1px solid #30363d;border-radius:4px;padding:4px 8px;font-size:11px;color:#e6edf3;pointer-events:none;white-space:nowrap;display:none;z-index:10}

@media(max-width:640px){
  .charts-row{grid-template-columns:1fr}
}

footer{text-align:center;padding:24px 0;border-top:1px solid #21262d;margin-top:32px;font-size:12px;color:#484f58}
footer a{color:#484f58}
footer a:hover{color:#58a6ff}

@media(max-width:640px){
  .stats-row{grid-template-columns:repeat(2,1fr)}
  .networks table{font-size:12px}
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

<div class="charts-row" id="charts-row" style="display:none">
  <div class="chart-card">
    <h2>Last 24 Hours</h2>
    <div class="disclaimer">Since last registry restart</div>
    <div style="position:relative">
      <svg id="chart-hourly" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-hourly"></div>
    </div>
  </div>
  <div class="chart-card">
    <h2>Last 7 Days</h2>
    <div class="disclaimer">Since last registry restart</div>
    <div style="position:relative">
      <svg id="chart-daily" viewBox="0 0 400 180" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="chart-tooltip" id="tip-daily"></div>
    </div>
  </div>
</div>

<div class="versions" id="versions"></div>

<div class="networks" id="networks">
  <h2>Networks</h2>
  <table>
    <thead><tr><th>Network</th><th>Members</th><th>Online</th><th>Requests</th><th>Trust Links</th></tr></thead>
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
function renderNetworks(networks){
  var wrap=document.getElementById('networks');
  var tbody=document.getElementById('net-tbody');
  if(!networks||!networks.length){wrap.style.display='none';var st=document.getElementById('token-status');if(getToken()){st.textContent='invalid token';st.className='status'}return}
  wrap.style.display='block';
  var st=document.getElementById('token-status');st.textContent='authenticated';st.className='status ok';
  var html='';
  networks.forEach(function(n){
    html+='<tr><td>'+n.name+' <span class="net-id">#'+n.id+'</span></td><td>'+fmt(n.members)+'</td><td>'+fmt(n.online)+'</td><td>'+fmt(n.requests)+'</td><td>'+fmt(n.trust_links)+'</td></tr>';
  });
  tbody.innerHTML=html;
}
function renderChart(svgId,tipId,samples,labelFn){
  var svg=document.getElementById(svgId);
  var tip=document.getElementById(tipId);
  if(!samples||!samples.length){svg.innerHTML='';return}
  var W=400,H=180,padL=40,padR=10,padT=10,padB=30;
  var cW=W-padL-padR,cH=H-padT-padB;
  var vals=samples.map(function(s){return s.online_nodes||0});
  var maxV=Math.max.apply(null,vals);
  if(maxV===0)maxV=1;
  // Y-axis: nice round gridlines
  var step=Math.pow(10,Math.floor(Math.log10(maxV||1)));
  if(maxV/step<2)step=step/4;
  else if(maxV/step<5)step=step/2;
  var gridMax=Math.ceil(maxV/step)*step;
  if(gridMax===0)gridMax=1;
  var html='';
  // Grid lines
  for(var g=0;g<=gridMax;g+=step){
    var gy=padT+cH-(g/gridMax)*cH;
    html+='<line x1="'+padL+'" y1="'+gy+'" x2="'+(W-padR)+'" y2="'+gy+'" stroke="#21262d" stroke-width="1"/>';
    html+='<text x="'+(padL-4)+'" y="'+(gy+4)+'" fill="#484f58" font-size="10" text-anchor="end" font-family="monospace">'+g+'</text>';
  }
  // Build points
  var pts=[];
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-(vals[i]/gridMax)*cH;
    pts.push(x.toFixed(1)+','+y.toFixed(1));
  }
  var polyPts=pts.join(' ');
  // Area fill
  var firstX=padL+(vals.length>1?0:0.5)*cW;
  var lastX=padL+(vals.length>1?1:0.5)*cW;
  var areaFill=firstX.toFixed(1)+','+(padT+cH)+' '+polyPts+' '+lastX.toFixed(1)+','+(padT+cH);
  html+='<polygon points="'+areaFill+'" fill="#58a6ff" fill-opacity="0.15"/>';
  html+='<polyline points="'+polyPts+'" fill="none" stroke="#58a6ff" stroke-width="2"/>';
  // Data points and labels
  for(var i=0;i<vals.length;i++){
    var x=padL+(vals.length>1?i/(vals.length-1):0.5)*cW;
    var y=padT+cH-(vals[i]/gridMax)*cH;
    html+='<circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="3" fill="#58a6ff" stroke="#0a0e17" stroke-width="1.5"/>';
    var lbl=labelFn(samples[i]);
    html+='<text x="'+x.toFixed(1)+'" y="'+(padT+cH+16)+'" fill="#484f58" font-size="9" text-anchor="middle" font-family="monospace">'+lbl+'</text>';
    // Invisible hover rect per data point
    var rw=cW/(vals.length||1);
    html+='<rect x="'+(x-rw/2).toFixed(1)+'" y="'+padT+'" width="'+rw.toFixed(1)+'" height="'+cH+'" fill="transparent" data-val="'+vals[i]+'" data-lbl="'+lbl+'" data-x="'+x.toFixed(1)+'" data-y="'+y.toFixed(1)+'"/>';
  }
  svg.innerHTML=html;
  // Tooltip handlers
  svg.querySelectorAll('rect[data-val]').forEach(function(r){
    r.addEventListener('mouseenter',function(e){
      tip.textContent=r.getAttribute('data-lbl')+': '+r.getAttribute('data-val')+' online';
      tip.style.display='block';
      var svgRect=svg.getBoundingClientRect();
      var px=parseFloat(r.getAttribute('data-x'))/W*svgRect.width;
      tip.style.left=(px+4)+'px';
      tip.style.top='0px';
    });
    r.addEventListener('mouseleave',function(){tip.style.display='none'});
  });
}
function renderCharts(hourly,daily){
  var row=document.getElementById('charts-row');
  if((!hourly||!hourly.length)&&(!daily||!daily.length)){row.style.display='none';return}
  row.style.display='grid';
  renderChart('chart-hourly','tip-hourly',hourly||[],function(s){
    var d=new Date(s.ts*1000);
    return ('0'+d.getHours()).slice(-2)+':00';
  });
  renderChart('chart-daily','tip-daily',daily||[],function(s){
    var d=new Date(s.ts*1000);
    return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][d.getDay()]+' '+d.getDate();
  });
}
function update(){
  var url='/api/stats';
  var t=getToken();if(t)url+='?token='+encodeURIComponent(t);
  fetch(url).then(function(r){return r.json()}).then(function(d){
    document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('total-nodes').textContent=fmt(d.total_nodes||0);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes||0);
    document.getElementById('trust-links').textContent=fmt(d.total_trust_links||0);
    document.getElementById('uptime').textContent=uptimeStr(d.uptime_secs);
    renderVersions(d.versions);
    renderCharts(d.hourly,d.daily);
    renderNetworks(d.networks);
  }).catch(function(){})
}
initToken();update();setInterval(update,30000);
</script>
</body>
</html>`
