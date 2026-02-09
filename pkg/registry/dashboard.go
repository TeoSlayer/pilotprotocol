package registry

import (
	"encoding/json"
	"log/slog"
	"net/http"
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

header{display:flex;align-items:center;justify-content:space-between;padding:16px 0;border-bottom:1px solid #21262d;margin-bottom:32px}
header h1{font-size:20px;font-weight:600;color:#e6edf3}
header .links{display:flex;gap:16px;font-size:13px}
.uptime{font-size:12px;color:#8b949e;margin-top:4px}

.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:#e6edf3;display:block}
.stat-card .label{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}

.section{margin-bottom:32px}
.section h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d}

table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}
th{text-align:left;font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;padding:10px 16px;background:#0d1117;border-bottom:1px solid #21262d}
td{padding:10px 16px;border-bottom:1px solid #21262d;font-size:13px}
tr:last-child td{border-bottom:none}

.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
.status-online{background:#3fb950}
.status-offline{background:#484f58}

.diagrams{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:32px}
.diagram-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;text-align:center}
.diagram-card h3{font-size:13px;font-weight:600;color:#8b949e;margin-bottom:12px;text-transform:uppercase;letter-spacing:0.5px}

.empty{color:#484f58;font-style:italic;padding:20px;text-align:center}

footer{text-align:center;padding:24px 0;border-top:1px solid #21262d;margin-top:32px;font-size:12px;color:#484f58}
footer a{color:#484f58}
footer a:hover{color:#58a6ff}

@media(max-width:640px){
  .stats-row{grid-template-columns:1fr}
  .diagrams{grid-template-columns:1fr}
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
  <div class="links">
    <a href="https://github.com/TeoSlayer/pilotprotocol">GitHub</a>
    <a href="https://pilotprotocol.network">pilotprotocol.network</a>
  </div>
</header>

<div class="stats-row">
  <div class="stat-card">
    <span class="value" id="total-nodes">—</span>
    <span class="label">Total Nodes</span>
  </div>
  <div class="stat-card">
    <span class="value" id="active-nodes">—</span>
    <span class="label">Active Nodes</span>
  </div>
  <div class="stat-card">
    <span class="value" id="total-requests">—</span>
    <span class="label">Requests Served</span>
  </div>
</div>

<div class="diagrams">
  <div class="diagram-card">
    <h3>The Problem</h3>
    <svg viewBox="0 0 280 180" width="280" height="180" xmlns="http://www.w3.org/2000/svg">
      <!-- Agent boxes -->
      <rect x="10" y="20" width="70" height="36" rx="4" fill="#1a1e2a" stroke="#f85149" stroke-width="1.5"/>
      <text x="45" y="43" text-anchor="middle" fill="#c9d1d9" font-size="10" font-family="monospace">Agent A</text>
      <rect x="105" y="20" width="70" height="36" rx="4" fill="#1a1e2a" stroke="#f85149" stroke-width="1.5"/>
      <text x="140" y="43" text-anchor="middle" fill="#c9d1d9" font-size="10" font-family="monospace">Agent B</text>
      <rect x="200" y="20" width="70" height="36" rx="4" fill="#1a1e2a" stroke="#f85149" stroke-width="1.5"/>
      <text x="235" y="43" text-anchor="middle" fill="#c9d1d9" font-size="10" font-family="monospace">Agent C</text>
      <!-- NAT/Firewall bars -->
      <rect x="10" y="68" width="70" height="16" rx="2" fill="#21262d"/>
      <text x="45" y="80" text-anchor="middle" fill="#f85149" font-size="8" font-family="monospace">NAT</text>
      <rect x="105" y="68" width="70" height="16" rx="2" fill="#21262d"/>
      <text x="140" y="80" text-anchor="middle" fill="#f85149" font-size="8" font-family="monospace">FIREWALL</text>
      <rect x="200" y="68" width="70" height="16" rx="2" fill="#21262d"/>
      <text x="235" y="80" text-anchor="middle" fill="#f85149" font-size="8" font-family="monospace">NAT</text>
      <!-- Broken lines -->
      <line x1="45" y1="84" x2="140" y2="110" stroke="#f85149" stroke-width="1" stroke-dasharray="4,3"/>
      <line x1="140" y1="84" x2="140" y2="110" stroke="#f85149" stroke-width="1" stroke-dasharray="4,3"/>
      <line x1="235" y1="84" x2="140" y2="110" stroke="#f85149" stroke-width="1" stroke-dasharray="4,3"/>
      <!-- X marks -->
      <text x="85" y="100" fill="#f85149" font-size="14" font-family="monospace" font-weight="bold">✕</text>
      <text x="180" y="100" fill="#f85149" font-size="14" font-family="monospace" font-weight="bold">✕</text>
      <!-- Cloud -->
      <rect x="80" y="108" width="120" height="30" rx="4" fill="#1a1e2a" stroke="#484f58" stroke-width="1"/>
      <text x="140" y="127" text-anchor="middle" fill="#484f58" font-size="9" font-family="monospace">No addressability</text>
      <!-- Caption -->
      <text x="140" y="160" text-anchor="middle" fill="#8b949e" font-size="9" font-family="monospace">Isolated agents, custom integrations</text>
    </svg>
  </div>
  <div class="diagram-card">
    <h3>The Solution</h3>
    <svg viewBox="0 0 280 180" width="280" height="180" xmlns="http://www.w3.org/2000/svg">
      <!-- Agent boxes with addresses -->
      <rect x="10" y="20" width="70" height="36" rx="4" fill="#1a1e2a" stroke="#3fb950" stroke-width="1.5"/>
      <text x="45" y="38" text-anchor="middle" fill="#c9d1d9" font-size="10" font-family="monospace">Agent A</text>
      <text x="45" y="50" text-anchor="middle" fill="#3fb950" font-size="7" font-family="monospace">0:0000.0000.0001</text>
      <rect x="105" y="20" width="70" height="36" rx="4" fill="#1a1e2a" stroke="#3fb950" stroke-width="1.5"/>
      <text x="140" y="38" text-anchor="middle" fill="#c9d1d9" font-size="10" font-family="monospace">Agent B</text>
      <text x="140" y="50" text-anchor="middle" fill="#3fb950" font-size="7" font-family="monospace">0:0000.0000.0002</text>
      <rect x="200" y="20" width="70" height="36" rx="4" fill="#1a1e2a" stroke="#3fb950" stroke-width="1.5"/>
      <text x="235" y="38" text-anchor="middle" fill="#c9d1d9" font-size="10" font-family="monospace">Agent C</text>
      <text x="235" y="50" text-anchor="middle" fill="#3fb950" font-size="7" font-family="monospace">0:0000.0000.0003</text>
      <!-- Tunnel lines -->
      <line x1="45" y1="56" x2="140" y2="100" stroke="#3fb950" stroke-width="1.5"/>
      <line x1="140" y1="56" x2="140" y2="100" stroke="#3fb950" stroke-width="1.5"/>
      <line x1="235" y1="56" x2="140" y2="100" stroke="#3fb950" stroke-width="1.5"/>
      <line x1="45" y1="56" x2="235" y2="56" stroke="#3fb950" stroke-width="1" stroke-dasharray="3,2" opacity="0.4"/>
      <!-- Overlay network -->
      <rect x="70" y="96" width="140" height="30" rx="4" fill="#0d2818" stroke="#3fb950" stroke-width="1"/>
      <text x="140" y="115" text-anchor="middle" fill="#3fb950" font-size="9" font-family="monospace">Pilot Overlay Network</text>
      <!-- Checkmarks -->
      <text x="85" y="82" fill="#3fb950" font-size="14" font-family="monospace" font-weight="bold">✓</text>
      <text x="180" y="82" fill="#3fb950" font-size="14" font-family="monospace" font-weight="bold">✓</text>
      <!-- Caption -->
      <text x="140" y="148" text-anchor="middle" fill="#8b949e" font-size="9" font-family="monospace">Virtual addresses, P2P tunnels</text>
      <text x="140" y="162" text-anchor="middle" fill="#8b949e" font-size="9" font-family="monospace">NAT traversal, encryption</text>
    </svg>
  </div>
</div>

<div class="section">
  <h2>Networks</h2>
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Members</th></tr></thead>
    <tbody id="networks-body">
      <tr><td colspan="3" class="empty">Loading...</td></tr>
    </tbody>
  </table>
</div>

<div class="section">
  <h2>Nodes</h2>
  <table>
    <thead><tr><th>Address</th><th>Hostname</th><th>Status</th></tr></thead>
    <tbody id="nodes-body">
      <tr><td colspan="3" class="empty">Loading...</td></tr>
    </tbody>
  </table>
</div>

<footer>
  Pilot Protocol &middot;
  <a href="https://pilotprotocol.network">pilotprotocol.network</a> &middot;
  <a href="https://github.com/TeoSlayer/pilotprotocol">GitHub</a>
</footer>

</div>
<script>
function fmt(n){if(n>=1e6)return (n/1e6).toFixed(1)+'M';if(n>=1e3)return (n/1e3).toFixed(1)+'K';return n.toString()}
function uptimeStr(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');p.push(m+'m');return p.join(' ')}
function update(){
  fetch('/api/stats').then(function(r){return r.json()}).then(function(d){
    document.getElementById('total-nodes').textContent=fmt(d.total_nodes);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes);
    document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('uptime').textContent=uptimeStr(d.uptime_secs);
    var nb=document.getElementById('networks-body');
    nb.innerHTML='';
    if(d.networks&&d.networks.length){
      d.networks.forEach(function(n){
        var tr=document.createElement('tr');
        var td1=document.createElement('td');td1.textContent=n.id;
        var td2=document.createElement('td');td2.textContent=n.name;
        var td3=document.createElement('td');td3.textContent=n.members;
        tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);nb.appendChild(tr);
      });
    }else{nb.innerHTML='<tr><td colspan="3" class="empty">No networks</td></tr>'}
    var tb=document.getElementById('nodes-body');
    tb.innerHTML='';
    if(d.nodes&&d.nodes.length){
      d.nodes.forEach(function(n){
        var tr=document.createElement('tr');
        var td1=document.createElement('td');td1.textContent=n.address;
        var td2=document.createElement('td');td2.textContent=n.hostname||'\u2014';
        var td3=document.createElement('td');
        var dot=document.createElement('span');dot.className='status-dot '+(n.online?'status-online':'status-offline');
        td3.appendChild(dot);td3.appendChild(document.createTextNode(n.online?'Online':'Offline'));
        tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tb.appendChild(tr);
      });
    }else{tb.innerHTML='<tr><td colspan="3" class="empty">No nodes registered</td></tr>'}
  }).catch(function(){})
}
update();setInterval(update,5000);
</script>
</body>
</html>`
