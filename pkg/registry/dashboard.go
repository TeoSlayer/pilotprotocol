package registry

import (
	"encoding/json"
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

.graph-section{position:relative;margin-bottom:32px}
.graph-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #21262d}
.graph-header h2{font-size:14px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin:0;padding:0;border:none}
.graph-wrap{position:relative;background:#0d1117;border:1px solid #21262d;border-radius:8px;overflow:hidden}
#graph-canvas{display:block;width:100%;cursor:grab}
#graph-canvas:active{cursor:grabbing}
.fs-btn{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:5px 10px;color:#8b949e;font-family:inherit;font-size:12px;cursor:pointer;display:flex;align-items:center;gap:5px}
.fs-btn:hover{border-color:#58a6ff;color:#58a6ff}
.graph-wrap.fullscreen{position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:9999;border-radius:0;border:none}
.graph-wrap.fullscreen #graph-canvas{height:100vh!important}
.graph-wrap.fullscreen .fs-exit{position:absolute;top:16px;right:16px;z-index:10000}
.graph-tooltip{position:absolute;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px 12px;font-size:12px;color:#e6edf3;pointer-events:none;display:none;z-index:10;white-space:nowrap}
.graph-tooltip .tt-addr{color:#3fb950;font-weight:600}
.graph-tooltip .tt-tags{color:#58a6ff;margin-top:2px}
.graph-tooltip .tt-trust{color:#8b949e;margin-top:2px}

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

<div class="graph-section">
  <div class="graph-header">
    <h2>Trust Graph</h2>
    <button class="fs-btn" id="fs-btn" onclick="toggleFullscreen()">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M1 1h5V0H0v6h1V1zm14 0h-5V0h6v6h-1V1zM1 15h5v1H0v-6h1v5zm14 0h-5v1h6v-6h-1v5z"/></svg>
      Fullscreen
    </button>
  </div>
  <div class="graph-wrap" id="graph-wrap">
    <canvas id="graph-canvas" height="400"></canvas>
    <button class="fs-btn fs-exit" id="fs-exit" style="display:none" onclick="toggleFullscreen()">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M5 0v5H0v1h6V0H5zm6 0v6h6V5h-5V0h-1zM0 11h5v5h1v-6H0v1zm11 0v6h1v-5h5v-1h-6z"/></svg>
      Exit
    </button>
    <div class="graph-tooltip" id="graph-tooltip">
      <div class="tt-addr" id="tt-addr"></div>
      <div class="tt-tags" id="tt-tags"></div>
      <div class="tt-trust" id="tt-trust"></div>
    </div>
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
var gNodes=[],gEdges=[],simRunning=false,animId=null;
var camX=0,camY=0,camZ=1,dragX=0,dragY=0,dragging=false,hoveredNode=-1;
var dpr=window.devicePixelRatio||1;

function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString()}
function uptimeStr(s){var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);var p=[];if(d)p.push(d+'d');if(h)p.push(h+'h');p.push(m+'m');return p.join(' ')}

/* ---- Force-directed graph ---- */
function initGraph(nodes,edges){
  var addrMap={};
  gNodes=nodes.map(function(n,i){
    addrMap[n.address]=i;
    return{addr:n.address,tags:n.tags||[],online:n.online,trust:n.trust_links||0,
      x:(Math.random()-0.5)*600,y:(Math.random()-0.5)*400,vx:0,vy:0};
  });
  gEdges=[];
  edges.forEach(function(e){
    var si=addrMap[e.source],ti=addrMap[e.target];
    if(si!==undefined&&ti!==undefined)gEdges.push({s:si,t:ti});
  });
  camX=0;camY=0;camZ=1;
  if(!simRunning){simRunning=true;simLoop();}
}

function simLoop(){
  var alpha=0.3,repulse=30000,spring=0.002,damp=0.82,center=0.0001;
  var N=gNodes.length;
  for(var i=0;i<N;i++){
    for(var j=i+1;j<N;j++){
      var dx=gNodes[j].x-gNodes[i].x,dy=gNodes[j].y-gNodes[i].y;
      var d2=dx*dx+dy*dy;if(d2<1)d2=1;
      var f=repulse/d2;
      var dist=Math.sqrt(d2);
      var fx=dx/dist*f,fy=dy/dist*f;
      gNodes[i].vx-=fx*alpha;gNodes[i].vy-=fy*alpha;
      gNodes[j].vx+=fx*alpha;gNodes[j].vy+=fy*alpha;
    }
  }
  gEdges.forEach(function(e){
    var a=gNodes[e.s],b=gNodes[e.t];
    var dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1;
    var f=(d-400)*spring;
    a.vx+=dx/d*f*alpha;a.vy+=dy/d*f*alpha;
    b.vx-=dx/d*f*alpha;b.vy-=dy/d*f*alpha;
  });
  gNodes.forEach(function(n){n.vx-=n.x*center;n.vy-=n.y*center;});
  gNodes.forEach(function(n){n.vx*=damp;n.vy*=damp;n.x+=n.vx;n.y+=n.vy;});
  drawGraph();
  animId=requestAnimationFrame(simLoop);
}

function drawGraph(){
  var c=document.getElementById('graph-canvas');
  var ctx=c.getContext('2d');
  var W=c.width/dpr,H=c.height/dpr;
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);
  ctx.save();
  ctx.translate(W/2+camX,H/2+camY);
  ctx.scale(camZ,camZ);
  ctx.strokeStyle='rgba(63,185,80,0.12)';ctx.lineWidth=0.5;
  ctx.beginPath();
  gEdges.forEach(function(e){
    var a=gNodes[e.s],b=gNodes[e.t];
    ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);
  });
  ctx.stroke();
  gNodes.forEach(function(n,i){
    var r=Math.max(2,Math.min(6,1.5+n.trust*0.4));
    var col=n.online?'#3fb950':'#484f58';
    if(i===hoveredNode){col='#58a6ff';r+=2;}
    ctx.beginPath();ctx.arc(n.x,n.y,r,0,6.283);
    ctx.fillStyle=col;ctx.fill();
  });
  ctx.restore();
}

function resizeCanvas(){
  var c=document.getElementById('graph-canvas');
  var wrap=document.getElementById('graph-wrap');
  var isFs=wrap.classList.contains('fullscreen');
  var w=isFs?window.innerWidth:wrap.clientWidth;
  var h=isFs?window.innerHeight:400;
  c.width=w*dpr;c.height=h*dpr;
  c.style.width=w+'px';c.style.height=h+'px';
}

function findNode(mx,my){
  var c=document.getElementById('graph-canvas');
  var W=c.width/dpr,H=c.height/dpr;
  var gx=(mx-W/2-camX)/camZ,gy=(my-H/2-camY)/camZ;
  var best=-1,bd=Infinity;
  gNodes.forEach(function(n,i){
    var dx=n.x-gx,dy=n.y-gy,d=dx*dx+dy*dy;
    var r=Math.max(2,Math.min(6,1.5+n.trust*0.4))+4;
    if(d<(r*r)/(camZ*camZ)&&d<bd){bd=d;best=i;}
  });
  return best;
}

(function(){
  var c=document.getElementById('graph-canvas');
  c.addEventListener('mousedown',function(e){dragging=true;dragX=e.clientX;dragY=e.clientY;});
  window.addEventListener('mousemove',function(e){
    if(dragging){camX+=e.clientX-dragX;camY+=e.clientY-dragY;dragX=e.clientX;dragY=e.clientY;return;}
    var rect=c.getBoundingClientRect();
    var mx=e.clientX-rect.left,my=e.clientY-rect.top;
    var idx=findNode(mx,my);
    if(idx!==hoveredNode){
      hoveredNode=idx;
      var tt=document.getElementById('graph-tooltip');
      if(idx>=0){
        var n=gNodes[idx];
        document.getElementById('tt-addr').textContent=n.addr;
        document.getElementById('tt-tags').textContent=n.tags.length?n.tags.map(function(t){return'#'+t}).join(' '):'no tags';
        document.getElementById('tt-trust').textContent=n.trust+' trust link'+(n.trust!==1?'s':'');
        tt.style.display='block';
      }else{tt.style.display='none';}
    }
    if(hoveredNode>=0){
      var tt=document.getElementById('graph-tooltip');
      var rect2=c.getBoundingClientRect();
      tt.style.left=(e.clientX-rect2.left+12)+'px';
      tt.style.top=(e.clientY-rect2.top-10)+'px';
    }
  });
  window.addEventListener('mouseup',function(){dragging=false;});
  c.addEventListener('mouseleave',function(){hoveredNode=-1;document.getElementById('graph-tooltip').style.display='none';});
  c.addEventListener('wheel',function(e){
    e.preventDefault();
    var d=e.deltaY>0?0.9:1.1;
    camZ=Math.max(0.1,Math.min(10,camZ*d));
  },{passive:false});
  window.addEventListener('resize',resizeCanvas);
  resizeCanvas();
})();

function toggleFullscreen(){
  var wrap=document.getElementById('graph-wrap');
  var isFs=wrap.classList.contains('fullscreen');
  wrap.classList.toggle('fullscreen');
  document.getElementById('fs-exit').style.display=isFs?'none':'flex';
  resizeCanvas();
}
document.addEventListener('keydown',function(e){
  if(e.key==='Escape'){
    var wrap=document.getElementById('graph-wrap');
    if(wrap.classList.contains('fullscreen'))toggleFullscreen();
  }
});

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
    initGraph(allNodes,allEdges);
  }).catch(function(){})
}
document.getElementById('tag-filter').addEventListener('input',function(){currentPage=1;renderNodes()});
update();setInterval(update,30000);
</script>
</body>
</html>`
