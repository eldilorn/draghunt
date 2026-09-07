"""Local web control center for the Dealer (phase 1).

A zero-dependency dashboard on Python's http.server. Bound to 127.0.0.1 only:
the app can (later) fire real attacks, so nothing on the network may reach it.

Phase 1 does not fire. `deal` seals a case, generates synthetic telemetry to
investigate, and renders the live fire plan as a dry run. You investigate, submit
a verdict, and get graded. The sealed truth stays server-side until you submit.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import catalog as catalog_mod
from . import telemetry as telemetry_mod
from . import config as config_mod
from . import fire as fire_mod
from .siem import available as siem_available
from .grader import grade
from .schema import Verdict, load_ground_truth, SchemaError
from . import history as history_mod

SEAL_DIR = Path(".groundtruth")
TELEMETRY_DIR = Path("telemetry")
_CASE_ID = re.compile(r"^[0-9]{8}-[0-9]{6}-[A-Z0-9-]+$")

PAGE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>The Dealer</title>
<style>
:root{--bg:#0e1116;--panel:#171c24;--edge:#262d38;--ink:#e6edf3;--dim:#8b949e;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--ink)}
header{padding:14px 20px;border-bottom:1px solid var(--edge);display:flex;gap:12px;align-items:baseline}
h1{font-size:18px;margin:0}.tag{color:var(--dim);font-size:12px}
main{max-width:920px;margin:0 auto;padding:20px;display:grid;gap:16px}
.panel{background:var(--panel);border:1px solid var(--edge);border-radius:10px;padding:16px}
.panel h2{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim)}
button{background:var(--accent);color:#0b0f14;border:0;border-radius:7px;padding:8px 14px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--accent);border:1px solid var(--edge)}
button:disabled{opacity:.5;cursor:not-allowed}
select,input,textarea{background:#0b0f14;color:var(--ink);border:1px solid var(--edge);border-radius:6px;padding:7px}
label{display:block;font-size:12px;color:var(--dim);margin:8px 0 3px}
pre{background:#0b0f14;border:1px solid var(--edge);border-radius:8px;padding:12px;overflow:auto;max-height:300px;font-size:12px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.banner{padding:8px 12px;border-radius:8px;font-size:13px}
.banner.warn{background:#3a2d07;border:1px solid var(--warn);color:#f0d78c}
.banner.ok{background:#0f2a15;border:1px solid var(--ok);color:#93e6a5}
.hidden{display:none}
.mark-ok{color:var(--ok)}.mark-bad{color:var(--bad)}.mark-part{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:4px 6px;border-bottom:1px solid var(--edge)}
.big{font-size:26px;font-weight:700}
</style>
<header><h1>The Dealer</h1><span class=tag id=mode>control center · phase 1 · nothing fires</span></header>
<main>
 <div id=cfgbanner class=banner></div>

 <div class=panel>
  <h2>Deal a case</h2>
  <div class=row>
   <div><label>scenario</label><select id=scenario></select></div>
   <div><label>seed (optional)</label><input id=seed size=8 placeholder=random></div>
   <button id=dealbtn>Deal</button>
  </div>
 </div>

 <div class="panel hidden" id=casepanel>
  <h2>Case <span id=caseid class=tag></span></h2>
  <pre id=brief></pre>
  <h2>Fire plan (dry run)</h2>
  <pre id=fireplan></pre>
  <h2>Telemetry to investigate (synthetic)</h2>
  <pre id=telemetry></pre>
 </div>

 <div class="panel hidden" id=verdictpanel>
  <h2>Your verdict</h2>
  <div class=grid2>
   <div><label>disposition</label><select id=v_disp><option>malicious<option>benign<option>inconclusive</select></div>
   <div><label>technique (ATT&CK id)</label><input id=v_tech placeholder=T____></div>
   <div><label>source ip</label><input id=v_src></div>
   <div><label>account</label><input id=v_acct></div>
   <div><label>succeeded?</label><select id=v_succ><option value=false>no<option value=true>yes</select></div>
  </div>
  <label>narrative</label><textarea id=v_narr rows=3 style=width:100%></textarea>
  <div class=row style=margin-top:10px><button id=gradebtn>Grade it</button></div>
 </div>

 <div class="panel hidden" id=resultpanel>
  <h2>Result</h2>
  <div class=big id=score></div><div id=band class=tag></div>
  <table id=items></table>
  <div id=capnote class="banner warn hidden" style=margin-top:10px></div>
 </div>

 <div class=panel>
  <h2>Stats</h2>
  <pre id=stats>no reps yet</pre>
 </div>
</main>
<script>
let CASE=null;
const $=id=>document.getElementById(id);
async function api(path,body){const o=body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}:{};
 const r=await fetch(path,o);const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j;}
async function boot(){
 const s=await api('/api/state');
 $('scenario').innerHTML=s.deck.map(d=>`<option value="${d.id}">${d.id} — ${d.title}</option>`).join('');
 const b=$('cfgbanner');
 if(s.fire_ready){b.className='banner ok';b.textContent=`Range configured. SIEM adapter: ${s.siem}. (Live fire is phase 2.)`;}
 else{b.className='banner warn';b.textContent=`Dry-run only — range not configured (${s.gaps.join(', ')}). Offline reps work now; add range.toml for live fire.`;}
 renderStats(s.stats);
}
function renderStats(t){$('stats').textContent=t||'no reps yet';}
$('dealbtn').onclick=async()=>{
 const body={scenario:$('scenario').value};const seed=$('seed').value.trim();if(seed)body.seed=parseInt(seed,10);
 const c=await api('/api/deal',body);CASE=c.case_id;
 $('caseid').textContent=c.case_id;$('brief').textContent=c.brief;$('fireplan').textContent=c.fire_plan;
 $('telemetry').textContent=c.telemetry.join('\\n');
 $('casepanel').classList.remove('hidden');$('verdictpanel').classList.remove('hidden');
 $('resultpanel').classList.add('hidden');
 window.scrollTo(0,document.body.scrollHeight);
};
$('gradebtn').onclick=async()=>{
 if(!CASE)return;
 const verdict={disposition:$('v_disp').value,technique:$('v_tech').value,source_ip:$('v_src').value,
  account:$('v_acct').value,succeeded:$('v_succ').value==='true',narrative:$('v_narr').value};
 const r=await api('/api/grade',{case_id:CASE,verdict});
 $('score').textContent=r.total.toFixed(0)+' / 100';
 $('band').textContent=r.band;
 $('items').innerHTML='<tr><th>dimension<th>score<th>expected<th>you<th></tr>'+r.items.map(i=>{
  const cls=i.earned>=i.weight?'mark-ok':(i.earned>0?'mark-part':'mark-bad');
  const m=i.earned>=i.weight?'OK':(i.earned>0?'~':'X');
  return `<tr><td>${i.dimension}<td>${i.earned}/${i.weight}<td>${i.expected}<td>${i.got}<td class="${cls}">${m}${i.note?' '+i.note:''}</tr>`;
 }).join('');
 const cn=$('capnote');if(r.capped){cn.classList.remove('hidden');cn.textContent='Disposition polarity wrong — total capped.';}else cn.classList.add('hidden');
 $('resultpanel').classList.remove('hidden');
 renderStats(r.stats);
 window.scrollTo(0,document.body.scrollHeight);
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


class Handler(BaseHTTPRequestHandler):
    server_version = "Dealer/0.3"

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
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        try:
            if self.path == "/api/deal":
                self._deal(self._read_body())
            elif self.path == "/api/grade":
                self._grade(self._read_body())
            else:
                self._json(404, {"error": "not found"})
        except (SchemaError, config_mod.ConfigError) as exc:
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
            "stats": history_mod.stats().as_text(),
        })

    def _deal(self, body: dict):
        cfg = config_mod.load()
        case = catalog_mod.deal(scenario_id=body.get("scenario"), seed=body.get("seed"))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        case_id = f"{stamp}-{case.scenario.id}"
        SEAL_DIR.mkdir(parents=True, exist_ok=True)
        _case_path(case_id).write_text(json.dumps(catalog_mod.seal_dict(case.ground_truth), indent=2))
        TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)
        tel = telemetry_mod.generate(case)
        (TELEMETRY_DIR / f"{case_id}.log").write_text("\n".join(tel) + "\n")
        plan = fire_mod.build_plan(case, cfg)
        self._json(200, {
            "case_id": case_id,
            "brief": case.blind_brief,
            "fire_plan": plan.render(),
            "telemetry": tel,
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


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("refusing to bind off localhost: the app can fire attacks")
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Dealer control center on http://{host}:{port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
