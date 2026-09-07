"""Local web control center for Draghunt (phase 1).

A zero-dependency dashboard on Python's http.server. Bound to 127.0.0.1 only:
the app can (later) fire real attacks, so nothing on the network may reach it.

Phase 1 does not fire. `lay` seals a case, generates synthetic telemetry to
investigate, and renders the live fire plan as a dry run. You investigate, submit
a verdict, and get graded. The sealed truth stays server-side until you submit.
"""

from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import catalog as catalog_mod
from . import telemetry as telemetry_mod
from . import config as config_mod
from . import fire as fire_mod
from .fire import FireBlocked
from . import reset as reset_mod
from .reset import ResetBlocked
from .siem import available as siem_available, get_adapter
from .grader import grade
from .schema import Verdict, load_ground_truth, SchemaError
from . import history as history_mod

SEAL_DIR = Path(".groundtruth")
TELEMETRY_DIR = Path("telemetry")
_CASE_ID = re.compile(r"^[0-9]{8}-[0-9]{6}-[A-Z0-9-]+$")


def new_case_id(scenario_id: str, now=None) -> str:
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{scenario_id}-{secrets.token_hex(3).upper()}"

PAGE = r"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Draghunt</title>
<style>
:root{
 --page:#0a0c10; --surface:#12161c; --surface2:#171c24; --edge:rgba(255,255,255,.09);
 --ink:#e9eef5; --sec:#aab3bf; --muted:#6e7681; --grid:#232a33;
 --accent:#3987e5; --accent2:#7c5cff; --good:#0ca30c; --warning:#fab219; --critical:#d03b3b;
 --radius:14px; font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
}
@media (prefers-color-scheme: light){:root{
 --page:#f5f6f4; --surface:#ffffff; --surface2:#fbfbfa; --edge:rgba(11,11,11,.10);
 --ink:#0b0b0b; --sec:#52514e; --muted:#898781; --grid:#e1e0d9;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);-webkit-font-smoothing:antialiased}
a{color:var(--accent)}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 48px}

/* top bar */
header{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--page) 88%,transparent);
 backdrop-filter:blur(8px);border-bottom:1px solid var(--edge)}
.bar{max-width:1080px;margin:0 auto;padding:12px 20px;display:flex;align-items:center;gap:14px}
.brand{display:flex;align-items:center;gap:11px}
.brand svg{width:30px;height:30px;flex:none}
.brand h1{font-size:19px;margin:0;letter-spacing:.2px;
 background:linear-gradient(90deg,var(--ink),var(--accent));-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .sub{font-size:12px;color:var(--muted);margin-left:2px}
.pills{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.pill{font-size:12px;padding:4px 10px;border-radius:999px;border:1px solid var(--edge);color:var(--sec);white-space:nowrap}
.pill.ok{border-color:color-mix(in srgb,var(--good) 55%,transparent);color:var(--good);background:color-mix(in srgb,var(--good) 12%,transparent)}
.pill.warn{border-color:color-mix(in srgb,var(--warning) 55%,transparent);color:var(--warning);background:color-mix(in srgb,var(--warning) 12%,transparent)}

/* section + card */
.sechead{display:flex;align-items:center;gap:10px;margin:26px 2px 12px}
.sechead h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:0;font-weight:700}
.sechead .rule{flex:1;height:1px;background:var(--edge)}
.card{background:var(--surface);border:1px solid var(--edge);border-radius:var(--radius);padding:18px;
 box-shadow:0 1px 0 rgba(0,0,0,.15),0 8px 24px -18px rgba(0,0,0,.5)}
.card h3{margin:0 0 14px;font-size:13px;color:var(--sec);font-weight:600}
.grid{display:grid;gap:14px}
.cols2{grid-template-columns:1fr 1fr}
@media(max-width:720px){.cols2{grid-template-columns:1fr}}

/* KPI tiles */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media(max-width:720px){.kpis{grid-template-columns:repeat(2,1fr)}}
.tile{background:var(--surface);border:1px solid var(--edge);border-radius:var(--radius);padding:16px 16px 14px;position:relative;overflow:hidden}
.tile::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:.9}
.tile .v{font-size:32px;font-weight:750;line-height:1;font-variant-numeric:tabular-nums}
.tile .l{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-top:8px}
.tile.g::after{background:linear-gradient(90deg,var(--good),#3fbf6a)}
.tile.w::after{background:linear-gradient(90deg,var(--warning),#ffcf5c)}

/* tactic bars */
.bar-row{display:grid;grid-template-columns:1fr 2.2fr auto;align-items:center;gap:10px;padding:7px 0}
.bar-label{font-size:12.5px;color:var(--sec);display:flex;align-items:center;gap:7px}
.tag-weak{font-size:9.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--warning);
 border:1px solid color-mix(in srgb,var(--warning) 55%,transparent);border-radius:5px;padding:1px 5px}
.bar-track{height:12px;border-radius:6px;background:var(--grid);overflow:hidden}
.bar-fill{display:block;height:100%;border-radius:6px;transition:width .5s ease}
.bar-val{font-size:12.5px;color:var(--ink);font-variant-numeric:tabular-nums;min-width:26px;text-align:right}
.weakcall{margin-top:12px;font-size:12px;color:var(--muted)}
.weakcall b{color:var(--warning)}
.spark-meta{display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-top:6px}
.empty{color:var(--muted);font-size:13px;padding:6px 2px}

/* workflow */
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}
label{display:block;font-size:11px;color:var(--muted);margin:0 0 4px;text-transform:uppercase;letter-spacing:.05em}
select,input,textarea{background:var(--page);color:var(--ink);border:1px solid var(--edge);border-radius:8px;padding:9px 10px;font:inherit}
select:focus,input:focus,textarea:focus{outline:2px solid color-mix(in srgb,var(--accent) 55%,transparent);outline-offset:0}
button{background:linear-gradient(180deg,var(--accent),#2f6fca);color:#fff;border:0;border-radius:9px;
 padding:10px 18px;font-weight:650;cursor:pointer;font-size:14px}
button:hover{filter:brightness(1.08)}
button:disabled{opacity:.5;cursor:not-allowed;filter:none}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--edge);font-weight:600}
.check{display:flex;gap:7px;align-items:center;color:var(--sec);font-size:13px;text-transform:none;letter-spacing:0;margin:0}
.check input{width:15px;height:15px}
pre{background:var(--page);border:1px solid var(--edge);border-radius:10px;padding:12px;overflow:auto;
 max-height:300px;font-size:12px;font-family:ui-monospace,"SF Mono",Menlo,monospace;color:var(--sec)}
.hidden,[hidden]{display:none!important}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:560px){.grid2{grid-template-columns:1fr}}
.big{font-size:40px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--edge)}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
td{font-variant-numeric:tabular-nums}
.mk-ok{color:var(--good)}.mk-part{color:var(--warning)}.mk-bad{color:var(--critical)}
.stack{display:grid;gap:14px}
.subtle{font-size:12px;color:var(--muted);margin-top:8px}
.banner{margin-top:12px;padding:9px 12px;border-radius:9px;font-size:12.5px;
 background:color-mix(in srgb,var(--warning) 12%,transparent);border:1px solid color-mix(in srgb,var(--warning) 45%,transparent);color:var(--warning)}
</style>

<header><div class=bar>
 <div class=brand>
  <svg viewBox="0 0 256 256" aria-hidden=true><rect width=256 height=256 rx=56 fill="#0e1116"/>
   <path d="M32 200 Q92 168 116 176 T176 132" fill=none stroke="#58a6ff" stroke-width=12 stroke-linecap=round stroke-dasharray="1 30"/>
   <circle cx=188 cy=100 r=40 fill=none stroke="#3fb950" stroke-width=12/><circle cx=188 cy=100 r=9 fill="#3fb950"/>
   <line x1=188 y1=46 x2=188 y2=64 stroke="#3fb950" stroke-width=10 stroke-linecap=round/>
   <line x1=188 y1=136 x2=188 y2=154 stroke="#3fb950" stroke-width=10 stroke-linecap=round/>
   <line x1=134 y1=100 x2=152 y2=100 stroke="#3fb950" stroke-width=10 stroke-linecap=round/>
   <line x1=224 y1=100 x2=242 y2=100 stroke="#3fb950" stroke-width=10 stroke-linecap=round/></svg>
  <div><h1>Draghunt</h1></div><span class=sub>investigation range</span>
 </div>
 <div class=pills><span class=pill id=pillRange>range</span><span class=pill id=pillSiem>SIEM</span></div>
</div></header>

<div class=wrap>

 <div class=sechead><h2>Scoreboard</h2><span class=rule></span></div>
 <div class=kpis>
  <div class=tile><div class=v id=kpiHunts>0</div><div class=l>hunts run</div></div>
  <div class="tile g"><div class=v id=kpiSolved>—</div><div class=l>solved</div></div>
  <div class="tile w"><div class=v id=kpiStreak>0</div><div class=l>streak</div></div>
  <div class=tile><div class=v id=kpiAvg>—</div><div class=l>avg score</div></div>
 </div>
 <div id=emptyScores class="empty" style=margin-top:14px>No hunts yet. Lay a drag below, work the telemetry, and grade your verdict to start scoring.</div>
 <div id=scoreCharts class="grid cols2" style=margin-top:14px hidden>
  <div class=card><h3>Performance by tactic</h3><div id=tacticBars></div><div class=weakcall id=weakcall></div></div>
  <div class=card><h3>Score history</h3><div id=spark></div>
   <div class=spark-meta><span>oldest</span><span>last 20 hunts</span><span>latest</span></div></div>
 </div>

 <div class=sechead><h2>Run a hunt</h2><span class=rule></span></div>
 <div class=card>
  <div class=row>
   <div><label>scenario</label><select id=scenario></select></div>
   <div><label>seed</label><input id=seed size=8 placeholder=random></div>
   <button id=laybtn>Lay a drag</button>
   <label class=check><input type=checkbox id=firelive disabled> fire live</label>
   <label class=check><input type=checkbox id=resetfirst disabled> reset target first</label>
  </div>
  <div class=subtle id=layhint>Dry-run mode. Add a <code>range.toml</code> to fire against a real target and pull SIEM alerts.</div>
 </div>

 <div class="card stack hidden" id=huntcard style=margin-top:14px>
  <div><h3 style=margin:0>Hunt <span id=caseid style="color:var(--muted);font-weight:400"></span></h3></div>
  <pre id=brief></pre>
  <details><summary style="cursor:pointer;color:var(--sec);font-size:12px">fire plan (dry run)</summary><pre id=fireplan style=margin-top:8px></pre></details>
  <div><h3 id=telhead style=margin:0 0 8px>Telemetry to investigate</h3><pre id=telemetry></pre></div>
  <div id=alertsbox hidden><h3 style=margin:14px 0 8px>SIEM alerts <button id=pullbtn class=ghost style=padding:5px 10px>Pull from SIEM</button> <span id=alertstatus style="color:var(--muted);font-size:12px"></span></h3><div style=overflow:auto><table id=alerts></table></div></div>
 </div>

 <div class="card hidden" id=verdictcard style=margin-top:14px>
  <h3>Your verdict</h3>
  <div class=grid2>
   <div><label>disposition</label><select id=v_disp><option>malicious<option>benign<option>inconclusive</select></div>
   <div><label>technique (ATT&CK id)</label><input id=v_tech placeholder=T____></div>
   <div><label>source ip</label><input id=v_src></div>
   <div><label>account</label><input id=v_acct></div>
   <div><label>succeeded?</label><select id=v_succ><option value=false>no<option value=true>yes</select></div>
  </div>
  <label style=margin-top:10px>narrative</label><textarea id=v_narr rows=3 style=width:100%></textarea>
  <div class=row style=margin-top:12px><button id=gradebtn>Grade verdict</button></div>
 </div>

 <div class="card hidden" id=resultcard style=margin-top:14px>
  <h3>Result</h3>
  <div style=display:flex;align-items:baseline;gap:14px><span class=big id=score></span><span id=band style=color:var(--sec)></span></div>
  <table id=items style=margin-top:12px></table>
  <div id=capnote class="banner hidden"></div>
 </div>

</div>

<script>
const $=id=>document.getElementById(id);
let CASE=null;
async function api(path,body){const o=body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}:{};
 const r=await fetch(path,o);const j=await r.json();if(!r.ok)throw new Error(j.error||('HTTP '+r.status));return j;}

async function boot(){
 const s=await api('/api/state');
 $('scenario').innerHTML=s.deck.map(d=>`<option value="${d.id}">${d.id} — ${d.title}</option>`).join('');
 const pr=$('pillRange');
 if(s.fire_ready){pr.className='pill ok';pr.textContent='range: ready';}
 else{pr.className='pill warn';pr.textContent='range: dry-run';pr.title='not configured: '+s.gaps.join(', ');}
 $('firelive').disabled=!s.fire_ready;
 $('resetfirst').disabled=!(s.fire_ready&&s.reset_ready);$('resetfirst').checked=(s.fire_ready&&s.reset_ready);
 $('layhint').hidden=s.fire_ready;
 await loadScores();
 try{const h=await api('/api/siem-health');const ps=$('pillSiem');
  ps.className='pill '+(h.ok?'ok':'warn');ps.textContent='SIEM '+h.adapter+': '+(h.ok?'up':'down');ps.title=h.detail||'';}catch(e){}
}

async function loadScores(){renderScores(await api('/api/scores'));}
function renderScores(s){
 const has=s.attempts>0;
 $('emptyScores').hidden=has;$('scoreCharts').hidden=!has;
 $('kpiHunts').textContent=s.attempts;
 $('kpiSolved').textContent=has?Math.round(s.pass_rate)+'%':'—';
 $('kpiStreak').textContent=s.streak;
 $('kpiAvg').textContent=has?Math.round(s.avg_score):'—';
 if(!has)return;
 const bt=Object.entries(s.by_tactic).sort((a,b)=>a[1]-b[1]);
 $('tacticBars').innerHTML=bt.map(([t,v])=>{
  const weak=(t===s.weakest_tactic);const col=weak?'var(--warning)':'var(--accent)';
  return `<div class=bar-row title="${t}: ${Math.round(v)}/100">
   <span class=bar-label>${t}${weak?' <span class=tag-weak>weakest</span>':''}</span>
   <span class=bar-track><span class=bar-fill style="width:${v}%;background:${col}"></span></span>
   <span class=bar-val>${Math.round(v)}</span></div>`;}).join('');
 $('weakcall').innerHTML=s.weakest_tactic?`Weakest area: <b>${s.weakest_tactic}</b> — drill it next.`:'';
 renderSpark(s.recent||[]);
}
function renderSpark(recent){
 const el=$('spark');if(!recent.length){el.innerHTML='';return;}
 const W=320,H=68,pad=7,n=recent.length;
 const x=i=>n<=1?W/2:pad+i*(W-2*pad)/(n-1);
 const y=v=>H-pad-(v/100)*(H-2*pad);
 const pts=recent.map((r,i)=>[x(i),y(r.total)]);
 const line=pts.map(p=>p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ');
 const area=`${pad.toFixed(1)},${(H-pad).toFixed(1)} ${line} ${x(n-1).toFixed(1)},${(H-pad).toFixed(1)}`;
 const dots=recent.map((r,i)=>`<circle cx="${x(i).toFixed(1)}" cy="${y(r.total).toFixed(1)}" r="2.6" fill="${r.passed?'var(--good)':'var(--critical)'}"><title>${(r.scenario_id||'')} ${Math.round(r.total)}/100</title></circle>`).join('');
 const last=pts[pts.length-1];
 el.innerHTML=`<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" preserveAspectRatio="none" style="display:block">
  <defs><linearGradient id=sg x1=0 y1=0 x2=0 y2=1><stop offset=0 stop-color="var(--accent)" stop-opacity=.35/><stop offset=1 stop-color="var(--accent)" stop-opacity=0/></linearGradient>
   <line x1=${pad} y1=${y(50).toFixed(1)} x2=${W-pad} y2=${y(50).toFixed(1)} stroke="var(--grid)" stroke-width=1/></defs>
  <line x1=${pad} y1=${y(60).toFixed(1)} x2=${W-pad} y2=${y(60).toFixed(1)} stroke="var(--grid)" stroke-width=1 stroke-dasharray="2 4"/>
  <polygon points="${area}" fill="url(#sg)"/>
  <polyline points="${line}" fill=none stroke="var(--accent)" stroke-width=2 vector-effect=non-scaling-stroke stroke-linejoin=round stroke-linecap=round/>
  ${dots}<circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r=4 fill="var(--accent)"/></svg>`;
}

$('laybtn').onclick=async()=>{
 const fire=$('firelive').checked,reset=$('resetfirst').checked;
 if(fire&&!confirm((reset?'Revert the target to its snapshot AND ':'')+'fire a REAL attack against your configured target now?'))return;
 const body={scenario:$('scenario').value,fire,reset};const seed=$('seed').value.trim();if(seed)body.seed=parseInt(seed,10);
 $('laybtn').disabled=true;$('laybtn').textContent=fire?'Firing…':'Laying…';
 try{
  const c=await api('/api/lay',body);CASE=c.case_id;
  $('caseid').textContent=c.case_id;$('brief').textContent=c.brief;$('fireplan').textContent=c.fire_plan;
  if(c.fired){const r=c.fire_result;$('telhead').textContent='Live fire';
   const rs=(c.reset&&c.reset.length)?('reset:\n'+c.reset.map(x=>'  ['+(x.ok?'ok':'FAIL')+'] '+x.name+': '+x.detail).join('\n')+'\n\n'):'';
   $('telemetry').textContent=rs+'rc='+r.returncode+(r.error?(' · error='+r.error):' · ok')+'\ninvestigate your SIEM for  '+r.window.start+'  ..  '+r.window.end+(r.stdout?('\n\n'+r.stdout):'');
   $('alertsbox').hidden=false;$('alerts').innerHTML='';$('alertstatus').textContent='';
  }else{$('telhead').textContent='Telemetry to investigate';$('telemetry').textContent=c.telemetry.join('\n');$('alertsbox').hidden=true;}
  $('huntcard').classList.remove('hidden');$('verdictcard').classList.remove('hidden');$('resultcard').classList.add('hidden');
  $('huntcard').scrollIntoView({behavior:'smooth',block:'start'});
 }catch(e){alert('lay failed: '+e.message);}
 finally{$('laybtn').disabled=false;$('laybtn').textContent='Lay a drag';}
};

$('pullbtn').onclick=async()=>{
 if(!CASE)return;$('alertstatus').textContent='querying…';
 try{const r=await api('/api/alerts',{case_id:CASE});
  $('alertstatus').textContent=r.count+' alerts · '+r.window.start+' .. '+r.window.end;
  $('alerts').innerHTML='<tr><th>time<th>rule<th>lvl<th>source<th>description</tr>'+
   r.alerts.map(a=>`<tr><td>${a.timestamp}<td>${a.rule}<td>${a.level}<td>${a.source}<td>${a.description}</tr>`).join('');
 }catch(e){$('alertstatus').textContent='error: '+e.message;}
};

$('gradebtn').onclick=async()=>{
 if(!CASE)return;
 const v={disposition:$('v_disp').value,technique:$('v_tech').value,source_ip:$('v_src').value,account:$('v_acct').value,succeeded:$('v_succ').value==='true',narrative:$('v_narr').value};
 const r=await api('/api/grade',{case_id:CASE,verdict:v});
 $('score').textContent=r.total.toFixed(0)+' / 100';$('band').textContent=r.band;
 $('items').innerHTML='<tr><th>dimension<th>score<th>expected<th>you<th></tr>'+r.items.map(i=>{
  const cls=i.earned>=i.weight?'mk-ok':(i.earned>0?'mk-part':'mk-bad');const m=i.earned>=i.weight?'OK':(i.earned>0?'~':'X');
  return `<tr><td>${i.dimension}<td>${i.earned}/${i.weight}<td>${i.expected}<td>${i.got}<td class="${cls}">${m}${i.note?' '+i.note:''}</tr>`;}).join('');
 const cn=$('capnote');if(r.capped){cn.classList.remove('hidden');cn.textContent='Disposition polarity wrong — total capped.';}else cn.classList.add('hidden');
 $('resultcard').classList.remove('hidden');
 await loadScores();
 $('resultcard').scrollIntoView({behavior:'smooth',block:'start'});
};
boot();
</script>
"""


def _case_path(case_id: str) -> Path:
    if not _CASE_ID.match(case_id):
        raise SchemaError("bad case id")
    p = (SEAL_DIR / f"{case_id}.json").resolve()
    if p.parent != SEAL_DIR.resolve():
        raise SchemaError("path escape")
    return p


def _fire_window(case_id: str) -> dict | None:
    if not _CASE_ID.match(case_id):
        raise SchemaError("bad case id")
    p = SEAL_DIR / f"{case_id}.fire.json"
    if not p.exists():
        return None
    return json.loads(p.read_text()).get("window")


class Handler(BaseHTTPRequestHandler):
    server_version = "Draghunt/0.3"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n).decode()) if n else {}

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self._state()
        elif self.path == "/api/siem-health":
            self._siem_health()
        elif self.path == "/api/scores":
            self._scores()
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        try:
            if self.path == "/api/lay":
                self._lay(self._read_body())
            elif self.path == "/api/grade":
                self._grade(self._read_body())
            elif self.path == "/api/alerts":
                self._alerts(self._read_body())
            else:
                self._json(404, {"error": "not found"})
        except (SchemaError, config_mod.ConfigError, FireBlocked, ResetBlocked) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    # --- endpoints -----------------------------------------------------------
    def _state(self):
        cfg = config_mod.load()
        deck = catalog_mod.load_catalog()
        gaps = cfg.missing_for_fire()
        self._json(200, {
            "deck": [{"id": s.id, "title": s.title, "technique": s.technique,
                      "tactic": s.tactic} for s in deck.values()],
            "siem": cfg.siem.adapter,
            "siem_available": siem_available(),
            "fire_ready": not gaps,
            "gaps": gaps,
            "reset_mode": cfg.reset.mode,
            "reset_ready": cfg.reset.mode != "none",
            "stats": history_mod.stats().as_text(),
        })

    def _lay(self, body: dict):
        cfg = config_mod.load()
        fire = bool(body.get("fire"))
        case = catalog_mod.lay(scenario_id=body.get("scenario"), seed=body.get("seed"))
        case_id = new_case_id(case.scenario.id)
        SEAL_DIR.mkdir(parents=True, exist_ok=True)
        _case_path(case_id).write_text(json.dumps(catalog_mod.seal_dict(case.ground_truth), indent=2))

        if fire:
            plan = fire_mod.build_plan(case, cfg, live=True)
            if not plan.ready:
                raise SchemaError("range not configured: " + ", ".join(plan.gaps))
            reset_steps = []
            if bool(body.get("reset")) and cfg.reset.mode != "none":
                rr = reset_mod.reset_target(cfg, case.scenario.id, confirm=True)
                reset_steps = [{"name": st.name, "ok": st.ok, "detail": st.detail} for st in rr.steps]
            result = fire_mod.execute(plan, confirm=True)
            win = result.window()
            (SEAL_DIR / f"{case_id}.fire.json").write_text(json.dumps({
                "returncode": result.returncode, "started_utc": result.started_utc,
                "finished_utc": result.finished_utc, "window": win,
                "command": result.command, "error": result.error}, indent=2))
            self._json(200, {
                "case_id": case_id, "brief": case.blind_brief, "fired": True,
                "fire_plan": plan.render(),
                "reset": reset_steps,
                "fire_result": {"returncode": result.returncode, "ok": result.ok,
                                "error": result.error, "window": win,
                                "stdout": result.stdout[-2000:]},
            })
            return

        plan = fire_mod.build_plan(case, cfg, live=False)
        TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
        tel = telemetry_mod.generate(case)
        (TELEMETRY_DIR / f"{case_id}.log").write_text("\n".join(tel) + "\n")
        self._json(200, {
            "case_id": case_id, "brief": case.blind_brief, "fired": False,
            "fire_plan": plan.render(), "telemetry": tel,
        })

    def _grade(self, body: dict):
        case_id = body.get("case_id", "")
        gt = load_ground_truth(_case_path(case_id))
        v = Verdict.from_dict(body.get("verdict", {}))
        report = grade(gt, v)
        history_mod.record(report, gt)
        self._json(200, {
            "total": report.total, "band": report.band, "capped": report.capped,
            "items": [{"dimension": i.dimension, "weight": i.weight, "earned": i.earned,
                       "expected": i.expected, "got": i.got, "note": i.note} for i in report.items],
            "stats": history_mod.stats().as_text(),
        })


    def _scores(self):
        st = history_mod.stats().as_dict()
        st["recent"] = history_mod.recent(20)
        self._json(200, st)

    def _siem_health(self):
        cfg = config_mod.load()
        try:
            ok, detail = get_adapter(cfg.siem.adapter, cfg.siem.options).health()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        self._json(200, {"adapter": cfg.siem.adapter, "ok": ok, "detail": detail})

    def _alerts(self, body: dict):
        cfg = config_mod.load()
        window = _fire_window(body.get("case_id", ""))
        if not window:
            raise SchemaError("no fire window for this case (offline case, or not fired)")
        start = datetime.strptime(window["start"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        end = datetime.strptime(window["end"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        try:
            adapter = get_adapter(cfg.siem.adapter, cfg.siem.options)
            alerts = adapter.query_alerts(start, end, limit=int(body.get("limit", 200)))
        except Exception as exc:  # noqa: BLE001
            self._json(502, {"error": f"{cfg.siem.adapter} query failed: {exc}"})
            return
        self._json(200, {"window": window, "count": len(alerts), "alerts": [
            {"timestamp": a.timestamp, "rule": a.rule, "level": a.level,
             "source": a.source, "description": a.description} for a in alerts]})


_LOCALHOST = ("127.0.0.1", "localhost", "::1")


def make_httpd(host: str = "127.0.0.1", port: int = 8787) -> ThreadingHTTPServer:
    if host not in _LOCALHOST:
        raise ValueError("refusing to bind off localhost: the app can fire attacks")
    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    httpd = make_httpd(host, port)
    print(f"Draghunt control center on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
