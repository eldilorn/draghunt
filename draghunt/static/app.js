'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="session-token"]').content;
let settings, current = null, dirty = false, saving = null, saveTimer, pollTimer;
const fields = {disposition:'v_disp',technique:'v_tech',source_ip:'v_src',account:'v_acct',narrative:'v_narr',timeline:'v_timeline',assets:'v_assets',impact:'v_impact',actions:'v_actions',confidence:'v_confidence',self_review:'v_review'};

function node(tag, text, className) { const el = document.createElement(tag); if(text !== undefined) el.textContent = String(text); if(className) el.className = className; return el; }
function message(text, error=false) { $('message').textContent = text; $('message').classList.toggle('danger', error); }
async function api(path, body, raw=false) {
  const options = {headers:{'X-Draghunt-Token':token}};
  if(body !== undefined) { options.method='POST'; options.headers['Content-Type']='application/json'; options.body=JSON.stringify(body); }
  const response = await fetch(path, options);
  if(!response.ok) { const error = await response.json().catch(()=>({})); throw new Error(error.error || `HTTP ${response.status}`); }
  return raw ? response.text() : response.json();
}
function action(id, fn) {
  $(id).addEventListener('click', async () => {
    $(id).disabled = true;
    try { await fn(); } catch(error) { message(error.message,true); }
    finally { $(id).disabled = false; }
  });
}

/* -------- tab navigation -------- */
function showView(name) {
  for(const view of document.querySelectorAll('.view')) view.hidden = view.id !== `view-${name}`;
  for(const tab of document.querySelectorAll('.tab')) tab.setAttribute('aria-current', String(tab.dataset.view === name));
}
for(const tab of document.querySelectorAll('.tab')) tab.addEventListener('click', () => showView(tab.dataset.view));

/* -------- report drafting -------- */
function verdict() {
  const value = Object.fromEntries(Object.entries(fields).map(([key,id]) => [key,$(id).value.trim() || null]));
  value.disposition = $('v_disp').value;
  value.succeeded = $('v_succ').value === '' ? null : $('v_succ').value === 'true';
  value.evidence_ids = [...new Set($('v_evidence').value.split(/[\s,]+/).filter(Boolean))];
  return value;
}
function fillReport(value) {
  for(const [key,id] of Object.entries(fields)) $(id).value = value[key] || (key === 'disposition' ? 'inconclusive' : '');
  $('v_succ').value = value.succeeded == null ? '' : String(value.succeeded);
  $('v_evidence').value = (value.evidence_ids || []).join('\n');
}
async function saveDraft() {
  clearTimeout(saveTimer);
  if(saving) { await saving; if(dirty) return saveDraft(); return; }
  if(!current || current.submission || !dirty) return;
  const id=current.id, payload=verdict(), version=current.draft_version;
  dirty=false; $('saveStatus').textContent='Saving…';
  saving = api('/api/draft',{case_id:id,verdict:payload,version}).then(result => {
    if(current && current.id===id) { current.draft_version=result.draft_version; $('saveStatus').textContent='Draft saved'; }
  }).catch(error => { dirty=true; $('saveStatus').textContent='Draft not saved'; throw error; });
  try { await saving; } finally { saving=null; }
  if(dirty) await saveDraft();
}
function markDirty() {
  if(!current || current.submission) return;
  dirty=true; $('saveStatus').textContent='Unsaved changes'; clearTimeout(saveTimer);
  saveTimer=setTimeout(() => saveDraft().catch(error => message(error.message,true)),800);
}
$('reportForm').addEventListener('input',markDirty);
window.addEventListener('beforeunload',event => { if(dirty || saving) { event.preventDefault(); event.returnValue=''; } });

/* -------- cases + scores -------- */
async function loadCases() {
  const cases = await api('/api/cases'), selected=current?.id || null;
  $('caseList').replaceChildren(...cases.map(c => {
    const button=node('button',undefined,'case-button'); button.type='button'; button.dataset.caseId=c.id;
    button.setAttribute('aria-current',String(c.id===selected));
    button.append(node('span',c.title),node('span',`${c.state.replaceAll('_',' ')} · ${new Date(c.created_utc).toLocaleString()}`,'subtle'),node('span',c.id.slice(-8),'subtle'));
    button.addEventListener('click',()=>openCase(c.id).catch(error=>message(error.message,true)));
    return button;
  }));
  if(!cases.length) $('caseList').append(node('p','No exercises yet. Run one above.','hint'));
  $('welcome').hidden = cases.length > 0;   // first-run orientation until the first exercise exists
  return cases;
}
function table(headers, rows) {
  const el=node('table'), head=node('tr'); head.append(...headers.map(h=>node('th',h)));
  const thead=node('thead'); thead.append(head); el.append(thead);
  const body=node('tbody'); for(const row of rows) { const tr=node('tr'); tr.append(...row.map(value=>node('td',value == null ? '—' : value))); body.append(tr); } el.append(body); return el;
}
async function loadScores() {
  const s=await api('/api/scores');
  $('kpiHunts').textContent=s.attempts; $('kpiSolved').textContent=s.attempts ? `${Math.round(s.pass_rate)}%` : '—';
  $('kpiAvg').textContent=s.attempts ? Math.round(s.avg_score) : '—'; $('kpiReport').textContent=s.attempts ? Math.round(s.report_average) : '—';
  $('streak').textContent=`Current passing streak: ${s.streak}`;
  const bars=Object.entries(s.by_tactic).sort((a,b)=>a[1]-b[1]).map(([t,v])=>{ const row=node('div',undefined,'bar-row'); const progress=node('progress'); progress.max=100; progress.value=v; progress.setAttribute('aria-label',`${t}: ${v}/100`); row.append(node('span',t,'bar-label'),progress,node('span',Math.round(v),'bar-val')); return row; });
  $('tacticBars').replaceChildren(...(bars.length?bars:[node('p','Complete an exercise to see progress.','empty')]));
  $('modeScores').replaceChildren(table(['Mode','Cases','Accuracy'],Object.entries(s.by_mode).map(([mode,v])=>[mode,v.attempts,`${Math.round(v.avg_score)}/100`])));
  $('findingHistory').replaceChildren(table(['Submitted','Mode','Case','Accuracy'],s.recent.map(r=>[new Date(r.ts).toLocaleString(),r.mode,r.scenario_id,`${r.total}/100`])));
  $('detectionHistory').replaceChildren(table(['Case','Rule / revision','Control','Matches','Result'],s.detections.map(d=>[d.case_id.slice(-8),`${d.rule_id} / ${d.revision}`,d.control?'Benign':'Positive',d.matches,d.passed?'Pass':'Fail'])));
}

/* -------- events + investigation -------- */
function renderEvents() {
  const needle=$('eventFilter').value.toLowerCase();
  const events=(current?.events || []).filter(e => JSON.stringify(e).toLowerCase().includes(needle));
  const elements=events.slice(0,250).map(event => {
    const detail=node('details',undefined,'event'), summary=node('summary');
    const preview=event.description || event.raw.full_log || event.rule || 'Event';
    summary.textContent=`${event.event_id} · ${event.timestamp || ''} ${String(preview).slice(0,180)}`;
    const cite=node('button','Cite','ghost sm'); cite.type='button'; cite.disabled=Boolean(current.submission);
    cite.addEventListener('click',()=>{ const ids=new Set(verdict().evidence_ids); ids.add(event.event_id); $('v_evidence').value=[...ids].join('\n'); markDirty(); });
    detail.append(summary,node('pre',JSON.stringify(event.raw,null,2)),cite); return detail;
  });
  $('events').replaceChildren(node('p',`${events.length} matching events${events.length>250?' · showing 250; narrow your search':''}`,'hint'),...elements);
}
$('eventFilter').addEventListener('input',renderEvents);
function renderAnswerKey(debrief) {
  const t=debrief.truth, sc=debrief.scenario;
  const disposition={malicious:'Malicious activity',benign:'Benign activity'}[t.disposition] || 'Inconclusive';
  const technique=t.technique ? `Technique ${t.technique} (${t.tactic}).` : `No ATT&CK technique applies (${t.tactic}).`;
  const who=[t.source_ip ? `Source ${t.source_ip}` : null, t.account ? `account ${t.account}` : null].filter(Boolean).join(', ');
  const outcome=t.succeeded===true ? 'The objective succeeded.' : t.succeeded===false ? 'The objective did not succeed.' : 'Whether the objective succeeded was not observable.';
  $('answerKey').replaceChildren(node('p',`This was: ${sc.title}`,'answer-title'),
    node('p',`${disposition}. ${technique} ${who ? who+'. ' : ''}${outcome}`),
    node('p',sc.brief,'hint'));
}
function renderStepper(doc) {
  const order=['evidence','report','debrief'];
  const step=doc.submission ? 'debrief' : doc.draft_version > 0 ? 'report' : 'evidence';
  for(const li of $('stepper').children) {
    li.setAttribute('aria-current',String(li.dataset.step===step));
    li.classList.toggle('done',order.indexOf(li.dataset.step) < order.indexOf(step));
  }
}
function renderCase(doc, fill=true) {
  current=doc;
  $('caseCard').hidden=false; $('caseTitle').textContent=doc.title;
  $('caseMeta').textContent=doc.mode==='live' ? `${doc.id} · live · target ${doc.target}` : `${doc.id} · synthetic · fictional events, nothing touched your lab`;
  renderStepper(doc);
  $('caseStatus').textContent=doc.error || doc.state.replaceAll('_',' '); $('caseStatus').classList.toggle('danger',Boolean(doc.error)); $('brief').textContent=doc.brief;
  $('diagnosticsBox').hidden=!doc.diagnostics; $('diagnostics').textContent=doc.diagnostics ? JSON.stringify(doc.diagnostics,null,2) : '';
  $('liveTools').hidden=doc.mode!=='live' || !doc.window;
  const info=Object.values(doc.collections).map(c=>`${c.kind}: ${c.event_ids.length}/${c.total} saved in latest snapshot · ${c.complete?'complete snapshot':'PARTIAL'} · ${c.fetched_utc}${c.detail?' · '+c.detail:''}`);
  if(doc.telemetry_ready_after) info.push(`Wait until ${doc.telemetry_ready_after}, then refresh alerts before judging a missing detection.`);
  if(doc.mode==='live' && doc.events.length===0) info.push('No evidence collected yet. An empty alert result does not establish that no activity occurred.');
  $('collectionStatus').textContent=info.join('\n'); renderEvents();
  const reportAvailable=['investigating','awaiting_telemetry','submitted'].includes(doc.state);
  $('reportCard').hidden=!reportAvailable; $('reportFields').disabled=Boolean(doc.submission);
  if(fill) { fillReport(doc.submission ? doc.submission.verdict : doc.draft); dirty=false; $('saveStatus').textContent=doc.submission?'Submitted':doc.draft_version?'Draft saved':''; }
  $('resultCard').hidden=!doc.submission; $('replaybtn').hidden=!doc.submission;
  $('detectionCard').hidden=!(doc.submission && doc.mode==='live');
  if(doc.submission) {
    const finding=doc.submission.finding_score, report=doc.submission.report_score;
    $('score').textContent=`Finding accuracy: ${finding.total}/100 · ${finding.band}`;
    $('reportScore').textContent=`Report completeness: ${report.total}/100`; $('reportNote').textContent=report.note;
    renderAnswerKey(doc.debrief);
    $('reportChecks').replaceChildren(...Object.entries(report.checks).map(([key,ok])=>node('p',`${ok?'✓':'Missing:'} ${key.replaceAll('_',' ')}`)));
    $('gradeItems').replaceChildren(...table(['Finding','Points','Expected','Reported'],finding.items.map(i=>[i.dimension,i.weight?`${i.earned}/${i.weight}`:'Not scored',i.weight?i.expected:'Not observable / applicable',i.got])).children);
    $('debrief').textContent=JSON.stringify(doc.debrief,null,2);
    if(fill && doc.debrief.truth.disposition==='benign') { $('ruleMin').value='0'; $('ruleMax').value='0'; }
    $('detectionResults').replaceChildren(table(['Revision','Matches','Expected','Result','Latency'],doc.detections.map(d=>[d.revision,d.matches,`${d.minimum}..${d.maximum ?? 'any'}`,d.passed?'Pass':'Fail',d.latency_seconds == null ? '—' : `${d.latency_seconds}s`])));
  }
  clearTimeout(pollTimer);
  if(doc.active) pollTimer=setTimeout(()=>poll(doc.id),1500);
}
async function poll(id) {
  try { const doc=await api(`/api/case?id=${encodeURIComponent(id)}`); if(current?.id===id) { renderCase(doc,false); if(!doc.active) await loadCases(); } }
  catch(error) { message(error.message,true); }
}
async function openCase(id) {
  if(!id) return;
  await saveDraft(); const doc=await api(`/api/case?id=${encodeURIComponent(id)}`); renderCase(doc); localStorage.setItem('activeCase',id);
  document.querySelectorAll('[data-case-id]').forEach(button=>button.setAttribute('aria-current',String(button.dataset.caseId===id)));
}

/* -------- run controls -------- */
function confirmLive(reset) {
  const px=settings.reset_target;
  const resetText=reset?`Reset mode ${settings.reset_mode}. ${['both','snapshot'].includes(settings.reset_mode)?`Revert VM ${px.vmid} on ${px.node} to snapshot ${px.snapshot}. `:''}`:'';
  return window.confirm(`${resetText}Run a real exercise against ${settings.target}?`);
}
function liveReason() {
  const el=$('liveReason');
  const hasLive=settings.deck.some(d=>d.live);
  if(!settings.fire_ready) {
    el.hidden=false; el.replaceChildren(node('span','Add your lab details to run live. Missing: '+(settings.gaps.join(', ')||'range configuration')+'. '));
    const link=node('button','Open Settings','ghost sm'); link.type='button'; link.addEventListener('click',()=>showView('settings')); el.append(link);
  } else if(!hasLive) {
    el.hidden=false; el.replaceChildren(node('span','Range is configured, but no live scenarios are available. In Settings, point the catalog directory at your private runner catalog and mark scenarios "live".'));
  } else { el.hidden=true; el.replaceChildren(); }
}
function updateRunControls() {
  const liveAvailable=settings.fire_ready && settings.deck.some(d=>d.live);
  $('firelive').disabled=!liveAvailable;
  if(!liveAvailable) $('firelive').checked=false;
  liveReason();
  const live=$('firelive').checked;
  $('resetfirst').disabled=!live || settings.reset_mode==='none';
  if($('resetfirst').disabled) $('resetfirst').checked=false;
  const selected=$('scenario').value;
  const options=[node('option','Blind draw'),...settings.deck.filter(d=>live ? d.live : d.offline).map(d=>{ const opt=node('option',d.title); opt.value=d.id; return opt; })];
  options[0].value=''; $('scenario').replaceChildren(...options); if(options.some(o=>o.value===selected)) $('scenario').value=selected;
  pickHint();
}
function pickHint() {
  $('pickHint').textContent=$('scenario').value
    ? 'A named drill tells you the category up front. The specifics are still randomized.'
    : "You won't be told which incident this is. Work it out from the evidence.";
}
$('scenario').addEventListener('change',pickHint);
$('firelive').addEventListener('change',updateRunControls);
action('laybtn',async()=>{
  await saveDraft(); const live=$('firelive').checked, reset=$('resetfirst').checked;
  if(live && !confirmLive(reset)) return;
  const body={scenario:$('scenario').value || null,fire:live,reset,confirm:live};
  if($('seed').value!=='') { const seed=Number($('seed').value); if(!Number.isSafeInteger(seed) || seed<0) throw new Error('Use a nonnegative whole-number seed.'); body.seed=seed; }
  const doc=await api('/api/lay',body); renderCase(doc); localStorage.setItem('activeCase',doc.id); await loadCases(); message(live?'Exercise queued. Progress is saved as it runs.':'Exercise ready. Investigate the events and write your report.');
  $('caseCard').scrollIntoView({behavior:'smooth',block:'start'});
});
action('refreshCases',loadCases);
action('savebtn',saveDraft);
action('pullbtn',async()=>{ if(!current) return; const id=current.id, limit=Number($('eventLimit').value); const doc=await api('/api/alerts',{case_id:id,kind:$('sourceKind').value,limit}); if(current.id===id) renderCase(doc,false); });
$('reportForm').addEventListener('submit',async event=>{
  event.preventDefault(); if(!current || current.submission) return;
  $('gradebtn').disabled=true;
  try { await saveDraft(); const doc=await api('/api/grade',{case_id:current.id,verdict:verdict()}); renderCase(doc); await loadScores(); await loadCases(); message('Report submitted. Your first score is recorded.'); }
  catch(error) { message(error.message,true); }
  finally { $('gradebtn').disabled=false; }
});
async function download(format) {
  if(!current) return; await saveDraft();
  const text=await api(`/api/export?id=${encodeURIComponent(current.id)}&format=${format}`,undefined,true);
  const url=URL.createObjectURL(new Blob([text],{type:'text/plain'}));
  const link=node('a'); link.href=url; link.download=current.id+(format==='json'?'.json':'.md'); link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
action('exportMd',()=>download('markdown')); action('exportJson',()=>download('json'));
action('replaybtn',async()=>{ if(!current?.submission) return; const live=current.mode==='live', reset=live && settings.reset_mode!=='none'; if(live && !confirmLive(reset)) return; const doc=await api('/api/lay',{replay_of:current.id,fire:live,reset,confirm:live}); renderCase(doc); await loadCases(); message('Replay started. Its report is saved separately from first-attempt scores.'); });
action('checkRule',async()=>{ const doc=await api('/api/detection',{case_id:current.id,rule_id:$('ruleId').value,revision:$('ruleRevision').value,rule_text:$('ruleText').value,minimum:Number($('ruleMin').value),maximum:$('ruleMax').value===''?null:Number($('ruleMax').value)}); renderCase(doc,false); await loadScores(); });

/* -------- settings -------- */
const CONFIG_FIELDS = ['control.catalog_dir','control.data_dir','attacker.host','attacker.user','attacker.ssh_key','target.host','target.user','target.agent_id','siem.indexer_url','siem.username','siem.password','siem.index','siem.events_index','siem.dashboard_url','siem.ca_file','siem.ingest_wait','reset.mode','reset.proxmox.api_url','reset.proxmox.token_id','reset.proxmox.token_secret','reset.proxmox.node','reset.proxmox.vmid','reset.proxmox.snapshot','reset.proxmox.target_host'];
const get = (obj,path) => path.split('.').reduce((o,k)=>o?.[k], obj);
function fieldId(path){ return 'cfg-'+path.replaceAll('.','-'); }
function fillConfig(cfg) {
  $('cfgPath').textContent=cfg.path;
  for(const path of CONFIG_FIELDS) {
    if(path.endsWith('password') || path.endsWith('token_secret')) continue;
    const value=get(cfg,path); const el=$(fieldId(path)); if(el) el.value=value == null ? '' : value;
  }
  $('siemPwKept').hidden=!cfg.siem.has_password;
  $('pxTokKept').hidden=!cfg.reset.proxmox.has_token_secret;
  $('cfg-siem-password').value=''; $('cfg-reset-proxmox-token_secret').value='';
  const el=$('cfgReadiness');
  if(!cfg.gaps.length) { el.className='readiness ok'; el.replaceChildren(node('span','✓ Ready to run against your lab.')); }
  else {
    el.className='readiness warn';
    el.replaceChildren(node('span','Fill these in to enable live runs:'));
    const ul=node('ul'); for(const gap of cfg.gaps) ul.append(node('li',gap)); el.append(ul);
  }
  if(cfg.binding_error) { el.className='readiness warn'; el.append(node('p',cfg.binding_error)); }
}
async function loadConfig(){ fillConfig(await api('/api/config')); }
$('cfgForm').addEventListener('submit',async event=>{
  event.preventDefault(); $('cfgSave').disabled=true; $('cfgStatus').textContent='Saving…';
  try {
    const body={control:{},attacker:{},target:{},siem:{},reset:{proxmox:{}}};
    for(const path of CONFIG_FIELDS) {
      if(path==='control.data_dir') continue;                 // read-only; server preserves it
      const el=$(fieldId(path)); if(!el) continue;
      const value=el.value.trim();
      if((path.endsWith('password')||path.endsWith('token_secret')) && value==='') continue;  // blank keeps existing
      const keys=path.split('.'); let target=body;
      for(const key of keys.slice(0,-1)) target=target[key] ??= {};
      target[keys.at(-1)]=value;
    }
    const cfg=await api('/api/config',body); fillConfig(cfg);
    settings=await api('/api/state'); updateRunControls(); setRangePill();
    $('cfgStatus').textContent='Saved. Environment updated.';
  } catch(error) { $('cfgStatus').textContent=''; message(error.message,true); }
  finally { $('cfgSave').disabled=false; }
});

/* -------- boot -------- */
function setRangePill() {
  const liveAvailable=settings.fire_ready && settings.deck.some(d=>d.live);
  const pill=$('rangeStatus'); pill.textContent=liveAvailable?'Live range':'Synthetic mode'; pill.classList.toggle('live',liveAvailable);
  pill.title=liveAvailable ? `Live range: exercises can run against ${settings.target}.` : 'Synthetic mode: fictional events generated on this machine. Nothing touches your lab.';
  $('rangeDetail').textContent=liveAvailable?`Target: ${settings.target}.`:'Synthetic exercises are ready. Add your lab in Settings to run live.';
}
async function boot() {
  settings=await api('/api/state');
  setRangePill(); updateRunControls();
  $('sourceKind').querySelector('option[value="events"]').disabled=!settings.events_available;
  if(settings.dashboard_url) { try { const url=new URL(settings.dashboard_url); if(['http:','https:'].includes(url.protocol)) { $('wazuhLink').href=url.href; $('wazuhLink').hidden=false; } } catch{} }
  await loadConfig(); await loadScores();
  const cases=await loadCases(); const previous=localStorage.getItem('activeCase');
  const selected=cases.find(c=>c.id===previous) || cases.find(c=>c.state!=='submitted') || cases[0];
  if(selected) await openCase(selected.id);
}
boot().catch(error=>message(error.message,true));
