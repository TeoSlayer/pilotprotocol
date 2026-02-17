package registry

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
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

	mux.HandleFunc("/api/badge/tags", func(w http.ResponseWriter, r *http.Request) {
		stats := s.GetDashboardStats()
		c := "#f59e0b"
		if stats.UniqueTags == 0 {
			c = "#9f9f9f"
		}
		serveBadge(w, "tags", fmtCount(stats.UniqueTags), c)
	})

	// pprof endpoints for live profiling
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

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

.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:32px}
.stat-card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:#e6edf3;display:block}
.stat-card .label{font-size:12px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-top:4px}

.section{margin-bottom:32px}
.section h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d}

table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}
th{text-align:left;font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;padding:10px 16px;background:#0d1117;border-bottom:1px solid #21262d}
td{padding:10px 16px;border-bottom:1px solid #21262d;font-size:13px}
tr:last-child td{border-bottom:none}

.tag{display:inline-block;background:#1f2937;border:1px solid #30363d;border-radius:12px;padding:2px 10px;font-size:11px;color:#58a6ff;margin:2px 4px 2px 0;white-space:nowrap}
.tag-filter{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:8px 12px;color:#c9d1d9;font-family:inherit;font-size:13px;width:100%;margin-bottom:12px;outline:none}
.tag-filter:focus{border-color:#58a6ff}
.tag-filter::placeholder{color:#484f58}
.empty{color:#484f58;font-style:italic;padding:20px;text-align:center}

.pagination{display:flex;align-items:center;justify-content:center;gap:8px;margin-top:12px;font-size:13px}
.pagination button{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:6px 12px;color:#c9d1d9;font-family:inherit;font-size:13px;cursor:pointer}
.pagination button:hover{border-color:#58a6ff;color:#58a6ff}
.pagination button:disabled{opacity:0.3;cursor:default;border-color:#30363d;color:#c9d1d9}
.pagination .page-info{color:#8b949e}

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
  <div class="links">
    <a href="https://github.com/TeoSlayer/pilotprotocol">GitHub</a>
    <a href="https://pilotprotocol.network">pilotprotocol.network</a>
  </div>
</header>

<div class="stats-row">
  <div class="stat-card">
    <span class="value" id="total-requests">—</span>
    <span class="label">Total Requests</span>
  </div>
  <div class="stat-card">
    <span class="value" id="active-nodes">—</span>
    <span class="label">Online Nodes</span>
  </div>
  <div class="stat-card">
    <span class="value" id="trust-links">—</span>
    <span class="label">Trust Links</span>
  </div>
  <div class="stat-card">
    <span class="value" id="unique-tags">—</span>
    <span class="label">Unique Tags</span>
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
  <input type="text" id="tag-filter" class="tag-filter" placeholder="Filter by tag...">
  <table>
    <thead><tr><th>Address</th><th>Status</th><th>Trust</th><th>Tags</th></tr></thead>
    <tbody id="nodes-body">
      <tr><td colspan="4" class="empty">Loading...</td></tr>
    </tbody>
  </table>
  <div class="pagination" id="pagination"></div>
</div>

<footer>
  Pilot Protocol &middot;
  <a href="https://pilotprotocol.network">pilotprotocol.network</a> &middot;
  <a href="https://github.com/TeoSlayer/pilotprotocol">GitHub</a>
</footer>

</div>
<script>
var allNodes=[],allEdges=[],currentPage=1,pageSize=25;

function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function uptimeStr(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');p.push(m+'m');return p.join(' ')}

/* ---- Table rendering ---- */
function getFiltered(){
  var filter=document.getElementById('tag-filter').value;
  if(!filter)return allNodes;
  var q=filter.toLowerCase().replace(/^#/,'');
  return allNodes.filter(function(n){return n.tags&&n.tags.some(function(t){return t.indexOf(q)>=0})});
}
function renderNodes(){
  var tb=document.getElementById('nodes-body');
  tb.innerHTML='';
  var filtered=getFiltered();
  var totalPages=Math.max(1,Math.ceil(filtered.length/pageSize));
  if(currentPage>totalPages)currentPage=totalPages;
  var start=(currentPage-1)*pageSize;
  var page=filtered.slice(start,start+pageSize);
  if(page.length){
    page.forEach(function(n){
      var tr=document.createElement('tr');
      var td1=document.createElement('td');td1.textContent=n.address;
      var td2=document.createElement('td');
      var dot=document.createElement('span');dot.style.cssText='display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:'+(n.online?'#3fb950':'#484f58');
      td2.appendChild(dot);td2.appendChild(document.createTextNode(n.online?'Online':'Offline'));td2.style.color=n.online?'#3fb950':'#484f58';
      var td3=document.createElement('td');td3.textContent=n.trust_links||0;td3.style.color=n.trust_links?'#58a6ff':'#484f58';
      var td4=document.createElement('td');
      if(n.tags&&n.tags.length){n.tags.forEach(function(t){var s=document.createElement('span');s.className='tag';s.textContent='#'+t;td4.appendChild(s)})}else{td4.textContent='\u2014'}
      tr.appendChild(td1);tr.appendChild(td2);tr.appendChild(td3);tr.appendChild(td4);tb.appendChild(tr);
    });
  }else{tb.innerHTML='<tr><td colspan="4" class="empty">No nodes'+(document.getElementById('tag-filter').value?' matching filter':' registered')+'</td></tr>'}
  var pg=document.getElementById('pagination');
  if(filtered.length<=pageSize){pg.innerHTML='';return}
  pg.innerHTML='';
  var prev=document.createElement('button');prev.textContent='Prev';prev.disabled=currentPage<=1;prev.onclick=function(){currentPage--;renderNodes()};
  var info=document.createElement('span');info.className='page-info';info.textContent='Page '+currentPage+' of '+totalPages+' ('+filtered.length+' nodes)';
  var next=document.createElement('button');next.textContent='Next';next.disabled=currentPage>=totalPages;next.onclick=function(){currentPage++;renderNodes()};
  pg.appendChild(prev);pg.appendChild(info);pg.appendChild(next);
}
function update(){
  fetch('/api/stats').then(function(r){return r.json()}).then(function(d){
    document.getElementById('total-requests').textContent=fmt(d.total_requests);
    document.getElementById('active-nodes').textContent=fmt(d.active_nodes||0);
    document.getElementById('trust-links').textContent=fmt(d.total_trust_links||0);
    document.getElementById('unique-tags').textContent=fmt(d.unique_tags||0);
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
    allNodes=d.nodes||[];
    allEdges=d.edges||[];
    renderNodes();
  }).catch(function(){})
}
document.getElementById('tag-filter').addEventListener('input',function(){currentPage=1;renderNodes()});
update();setInterval(update,30000);
</script>
</body>
</html>`
