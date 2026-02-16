#include "clawguard.h"

namespace clawguard {

std::string HttpServer::serve_dashboard() {
return R"DASH(<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClawGuard — System Monitor</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Outfit:wght@400;600;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#080810;--s1:#10101c;--s2:#181828;--bdr:#252540;--txt:#d8d8e8;--dim:#6868888;--red:#ff3355;--grn:#00ff88;--blu:#3388ff;--ylw:#ffbb22;--pur:#aa44ff}
body{font-family:'JetBrains Mono',monospace;background:var(--bg);color:var(--txt);min-height:100vh}
.hdr{padding:20px 28px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--bdr);background:linear-gradient(180deg,#0c0c1a,var(--bg))}
.hdr h1{font-family:'Outfit',sans-serif;font-size:24px;font-weight:800;letter-spacing:-1px}
.hdr h1 b{color:var(--red)}
.hdr .rt{font-size:11px;color:var(--dim);display:flex;align-items:center;gap:12px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--grn);animation:pls 2s infinite}
.dot.w{background:var(--ylw)}.dot.c{background:var(--red);animation:plc .6s infinite}
@keyframes pls{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes plc{0%,100%{opacity:1}50%{opacity:.15}}
.g{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;padding:20px 28px}
@media(max-width:1100px){.g{grid-template-columns:repeat(2,1fr)}}
@media(max-width:700px){.g{grid-template-columns:1fr;padding:12px}}
.c{background:var(--s1);border:1px solid var(--bdr);border-radius:14px;padding:20px;position:relative;overflow:hidden}
.c::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--red),var(--pur),var(--blu));opacity:.4}
.ct{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--dim);margin-bottom:14px}
.bn{font-family:'Outfit',sans-serif;font-size:52px;font-weight:800;line-height:1}
.bn.ok{color:var(--grn)}.bn.w{color:var(--ylw)}.bn.cr{color:var(--red)}
.bn u{font-size:18px;color:var(--dim);font-weight:400;text-decoration:none}
.ss{font-size:11px;color:var(--dim);margin-top:6px}
.bar{height:5px;background:var(--s2);border-radius:3px;margin-top:10px;overflow:hidden}
.bf{height:100%;border-radius:3px;transition:width .6s ease,background .4s}
.bf.ok{background:linear-gradient(90deg,#00ff88,#44ffbb)}.bf.w{background:linear-gradient(90deg,#ffbb22,#ffdd44)}.bf.cr{background:linear-gradient(90deg,#ff3355,#ff5577)}
.ch{width:100%;height:100px;margin-top:10px}
canvas{display:block}
.pl{list-style:none;font-size:11px}
.pl li{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--bdr)}
.pl li:last-child{border:0}
.pn{color:var(--txt);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pv{color:var(--blu);font-weight:600}
.al{font-size:11px}
.ai{padding:8px 10px;margin-bottom:6px;border-radius:8px;border-left:3px solid}
.ai.w{background:rgba(255,187,34,.06);border-color:var(--ylw)}
.ai.cr{background:rgba(255,51,85,.06);border-color:var(--red)}
.na{text-align:center;padding:20px;color:var(--grn);font-size:12px}
.tb{display:inline-block;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:600}
.tb.r{background:rgba(255,51,85,.12);color:var(--red)}
.tb.f{background:rgba(0,255,136,.12);color:var(--grn)}
.tb.s{background:rgba(104,104,136,.12);color:var(--dim)}
.wi{grid-column:span 3}
@media(max-width:1100px){.wi{grid-column:span 2}}
@media(max-width:700px){.wi{grid-column:span 1}}
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;font-size:11px}
.sg dt{color:var(--dim)}.sg dd{color:var(--txt);font-weight:600}
@media(max-width:700px){.sg{grid-template-columns:1fr 1fr}}
.dk{margin-bottom:10px}
.dk .dl{display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px}
.ct2{font-size:9px;text-transform:uppercase;letter-spacing:2px;color:var(--dim);margin:6px 0 10px}
</style></head><body>
<div class="hdr">
  <h1>🦞 <b>Claw</b>Guard</h1>
  <div class="rt"><div class="dot" id="dot"></div><span id="st">Connecting...</span><span id="hn">—</span><span id="ut">—</span></div>
</div>
<div class="g">
  <div class="c"><div class="ct">CPU Usage</div>
    <div class="bn ok" id="cv">—<u>%</u></div>
    <div class="ss" id="cl">Load: —</div>
    <div class="ss">Trend: <span class="tb s" id="ctr">—</span></div>
    <div class="bar"><div class="bf ok" id="cb" style="width:0"></div></div>
    <div class="ch"><canvas id="cc"></canvas></div>
  </div>
  <div class="c"><div class="ct">Memory</div>
    <div class="bn ok" id="mv">—<u>%</u></div>
    <div class="ss" id="md">— / —</div>
    <div class="ss">Trend: <span class="tb s" id="mtr">—</span></div>
    <div class="bar"><div class="bf ok" id="mb" style="width:0"></div></div>
    <div class="ch"><canvas id="mc"></canvas></div>
  </div>
  <div class="c"><div class="ct">Network I/O</div>
    <div class="ss" style="font-size:14px;margin-bottom:8px">▼ <span id="ni" style="color:var(--grn)">—</span>/s</div>
    <div class="ss" style="font-size:14px">▲ <span id="no" style="color:var(--blu)">—</span>/s</div>
    <div class="ch"><canvas id="nc"></canvas></div>
  </div>
  <div class="c"><div class="ct">Disk Usage</div><div id="dc">Loading...</div></div>
  <div class="c"><div class="ct">Top Processes <span id="pc" style="color:var(--dim)"></span></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
      <div>
        <div class="ct2">CPU</div>
        <ul class="pl" id="procs_cpu"></ul>
      </div>
      <div>
        <div class="ct2">Memory</div>
        <ul class="pl" id="procs_mem"></ul>
      </div>
    </div>
  </div>
  <div class="c"><div class="ct">Alerts</div>
    <div class="al" id="al"><div class="na">✓ All systems nominal</div></div>
  </div>
  <div class="c wi"><div class="ct">System Information</div>
    <dl class="sg" id="si"><dt>Loading...</dt><dd></dd></dl>
  </div>
</div>
<script>
const B=b=>{const u=['B','KB','MB','GB','TB'];let i=0,s=b;while(s>=1024&&i<4){s/=1024;i++}return s.toFixed(1)+' '+u[i]};
const S=(v,w=80,c=95)=>v>=c?'cr':v>=w?'w':'ok';
let cpuH=[],memH=[],niH=[],noH=[];const MX=60;

function draw(cv,sets,mx=100){
  const ctx=cv.getContext('2d'),w=cv.parentElement.clientWidth,h=cv.parentElement.clientHeight;
  cv.width=w*2;cv.height=h*2;ctx.scale(2,2);ctx.clearRect(0,0,w,h);
  ctx.strokeStyle='rgba(37,37,64,0.4)';ctx.lineWidth=.5;
  for(let i=0;i<=4;i++){const y=h/4*i;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}
  sets.forEach(({d,color})=>{
    if(d.length<2)return;
    const st=w/(MX-1),si=Math.max(0,d.length-MX);
    ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=1.5;
    for(let i=si;i<d.length;i++){
      const x=(i-si)*st,y=h-(d[i]/mx)*h;
      i===si?ctx.moveTo(x,y):ctx.lineTo(x,y);
    }
    ctx.stroke();
    ctx.lineTo((d.length-1-si)*st,h);ctx.lineTo(0,h);ctx.closePath();
    ctx.fillStyle=color.replace('1)','0.06)');ctx.fill();
  });
}

async function tick(){
  try{
    const[cur,trends,alerts,sys]=await Promise.all([
      fetch('/api/current').then(r=>r.json()),
      fetch('/api/trends').then(r=>r.json()),
      fetch('/api/alerts').then(r=>r.json()),
      fetch('/api/system').then(r=>r.json())
    ]);
    // CPU
    const cs=S(cur.cpu.usage);
    document.getElementById('cv').className='bn '+cs;
    document.getElementById('cv').innerHTML=cur.cpu.usage.toFixed(1)+'<u>%</u>';
    document.getElementById('cl').textContent='Load: '+cur.cpu.load_1m+' / '+cur.cpu.load_5m+' / '+cur.cpu.load_15m;
    document.getElementById('cb').style.width=cur.cpu.usage+'%';
    document.getElementById('cb').className='bf '+cs;
    cpuH.push(cur.cpu.usage);if(cpuH.length>MX*2)cpuH=cpuH.slice(-MX);
    // CPU trend
    const ctr=document.getElementById('ctr');
    ctr.textContent=trends.cpu_direction;
    ctr.className='tb '+(trends.cpu_direction==='rising'?'r':trends.cpu_direction==='falling'?'f':'s');
    
    // Memory
    const ms=S(cur.memory.usage);
    document.getElementById('mv').className='bn '+ms;
    document.getElementById('mv').innerHTML=cur.memory.usage.toFixed(1)+'<u>%</u>';
    document.getElementById('md').textContent=B(cur.memory.used)+' / '+B(cur.memory.total);
    document.getElementById('mb').style.width=cur.memory.usage+'%';
    document.getElementById('mb').className='bf '+ms;
    memH.push(cur.memory.usage);if(memH.length>MX*2)memH=memH.slice(-MX);
    const mtr=document.getElementById('mtr');
    mtr.textContent=trends.mem_direction;
    mtr.className='tb '+(trends.mem_direction==='rising'?'r':trends.mem_direction==='falling'?'f':'s');
    
    // Network
    document.getElementById('ni').textContent=B(cur.network.recv_rate);
    document.getElementById('no').textContent=B(cur.network.sent_rate);
    niH.push(cur.network.recv_rate);noH.push(cur.network.sent_rate);
    if(niH.length>MX*2){niH=niH.slice(-MX);noH=noH.slice(-MX)}
    
    // Disks
    let dh='';
    cur.disks.forEach(d=>{
      const ds=S(d.usage,85,95);
      dh+='<div class="dk"><div class="dl"><span>'+d.mount+'</span><span style="color:var(--'+(ds==='ok'?'grn':ds==='w'?'ylw':'red')+')">'+d.usage.toFixed(1)+'%</span></div>';
      dh+='<div class="bar"><div class="bf '+ds+'" style="width:'+d.usage+'%"></div></div>';
      dh+='<div class="ss">'+B(d.used)+' / '+B(d.total)+' ('+B(d.available)+' free)</div></div>';
    });
    document.getElementById('dc').innerHTML=dh||'<div class="ss">No disks detected</div>';
    
    // Processes
    let pcpu='',pmem='';
    (cur.processes.top_cpu||[]).slice(0,8).forEach(p=>{
      pcpu+='<li><span class="pn">'+p.name+'</span><span class="pv">'+(p.cpu_pct||0).toFixed(1)+'%</span></li>';
    });
    (cur.processes.top_mem||[]).slice(0,8).forEach(p=>{
      pmem+='<li><span class="pn">'+p.name+'</span><span class="pv">'+B(p.mem_bytes)+'</span></li>';
    });
    document.getElementById('procs_cpu').innerHTML=pcpu||'<li><span class="pn">—</span><span class="pv">—</span></li>';
    document.getElementById('procs_mem').innerHTML=pmem||'<li><span class="pn">—</span><span class="pv">—</span></li>';
    document.getElementById('pc').textContent='('+cur.processes.total+' total)';
    
    // Alerts
    if(alerts.alerts.length>0){
      let ah='';
      alerts.alerts.slice(-10).reverse().forEach(a=>{
        const ac=a.level==='critical'?'cr':'w';
        ah+='<div class="ai '+ac+'">'+a.message+'</div>';
      });
      document.getElementById('al').innerHTML=ah;
    }else{
      document.getElementById('al').innerHTML='<div class="na">✓ All systems nominal</div>';
    }
    
    // System info
    document.getElementById('si').innerHTML=
      '<dt>Hostname</dt><dd>'+sys.hostname+'</dd>'+
      '<dt>OS</dt><dd>'+sys.os+'</dd>'+
      '<dt>Kernel</dt><dd>'+sys.kernel+'</dd>'+
      '<dt>Arch</dt><dd>'+sys.arch+'</dd>'+
      '<dt>CPU Cores</dt><dd>'+sys.cpu_cores+'</dd>'+
      '<dt>Total RAM</dt><dd>'+sys.total_ram_fmt+'</dd>'+
      '<dt>Uptime</dt><dd>'+sys.uptime_fmt+'</dd>'+
      '<dt>ClawGuard</dt><dd>v'+sys.clawguard_version+'</dd>';
    
    document.getElementById('hn').textContent=sys.hostname;
    document.getElementById('ut').textContent='Up: '+sys.uptime_fmt;
    
    // Status dot
    const worst=Math.max(cur.cpu.usage,cur.memory.usage);
    const dot=document.getElementById('dot');
    dot.className='dot'+(worst>=95?' c':worst>=80?' w':'');
    document.getElementById('st').textContent=worst>=95?'CRITICAL':worst>=80?'Warning':'Healthy';
    
    // Charts
    draw(document.getElementById('cc'),[{d:cpuH,color:'rgba(0,255,136,1)'}]);
    draw(document.getElementById('mc'),[{d:memH,color:'rgba(170,68,255,1)'}]);
    const nmx=Math.max(1,...niH,...noH)*1.2;
    draw(document.getElementById('nc'),[{d:niH,color:'rgba(0,255,136,1)'},{d:noH,color:'rgba(51,136,255,1)'}],nmx);
    
  }catch(e){
    document.getElementById('st').textContent='Connection lost';
    document.getElementById('dot').className='dot c';
  }
}
tick();setInterval(tick,3000);
</script></body></html>)DASH";
}

} // namespace clawguard
