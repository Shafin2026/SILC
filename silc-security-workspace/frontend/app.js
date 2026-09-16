/* SILC frontend: readable vanilla JavaScript, no build step or external assets. */
"use strict";
const $ = (s, root = document) => root.querySelector(s);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const paths = {
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  upload:'<path d="M12 16V3m-4 4 4-4 4 4M4 15v5h16v-5"/>',
  download:'<path d="M12 3v13m-4-4 4 4 4-4M4 17v4h16v-4"/>',
  spark:'<path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z"/>',
  sliders:'<path d="M4 7h6m4 0h6M4 17h10m4 0h2"/><circle cx="12" cy="7" r="2"/><circle cx="16" cy="17" r="2"/>',
  book:'<path d="M12 5v16M3 4c4-1 6 0 9 2 3-2 5-3 9-2v15c-4-1-6 0-9 2-3-2-5-3-9-2z"/>',
  lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 8v-3"/>',
  help:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 2-2.5 2-2.5 4m0 3h.01"/>',
  close:'<path d="m6 6 12 12M18 6 6 18"/>',
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  alert:'<path d="M12 3 2 21h20zM12 9v5m0 3h.01"/>',
  search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l4 2"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  file:'<path d="M14 3H5v18h14V8zM14 3v5h5M8 13h8m-8 4h6"/>'
};
const icon = name => '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">' + (paths[name] || paths.file) + '</svg>';
document.querySelectorAll('[data-icon]').forEach(el => {el.outerHTML = icon(el.dataset.icon);});
const state = {data:null,rules:[],providers:[],view:"overview",query:"",severity:"all",status:"all",page:1,
  notes:Object.create(null),selected:new Set(),provider:"offline",brief:null,aiBusy:false,uploadBusy:false,detailId:null,
  mode:"analyst",type:"all",confidence:"all",aiConfidence:"all",bucket:null,timelineStart:0,
  logQuery:"",logProtocol:"all",logSeverity:"all",logLinked:false,logOffset:0,logTotal:0,
  detailTab:"reasoning",detailContext:null,contexts:new Map(),explanations:Object.create(null),
  briefTabs:Object.create(null),drafts:Object.create(null),audit:[]};
const titles = {overview:'Overview',alerts:'Alert queue',upload:'Analyze logs',briefing:'AI briefing',rules:'Detection rules',guide:'Project guide',logs:'Log explorer'};
const fmt = n => Number(n).toLocaleString('en-US');
const utcTime = t => new Date(t).toLocaleTimeString('en-GB',{timeZone:'UTC',hour:'2-digit',minute:'2-digit',second:'2-digit'});
const utcDate = t => new Date(t).toLocaleDateString('en-US',{timeZone:'UTC',month:'short',day:'numeric',year:'numeric'});
const noteKey = id => state.data.fingerprint + ':' + id;
const review = id => state.notes[noteKey(id)] || {status:'New',note:'',checks:[]};
const badge = s => '<span class="severity ' + esc(s.toLowerCase()) + '">' + esc(s) + '</span>';
const button = (label, action, type = '', glyph = '') => '<button type="button" class="btn ' + type + '" data-action="' + action + '">' + (glyph ? icon(glyph) : '') + label + '</button>';

async function api(path, options) {
  let response;
  try {response = await fetch(path, options);} catch (_) {throw new Error('Cannot reach the backend. Keep Terminal running and use the local address printed there.');}
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(typeof data?.detail === 'string' ? data.detail : 'The request could not be completed. Check your input and try again.');
  return data;
}
function toast(message) {const el = $('#toast');el.textContent = message;el.hidden = false;clearTimeout(toast.timer);toast.timer = setTimeout(() => {el.hidden = true;},4500);}
function heading(title, description, actions = '') {
  return '<div class="page-heading"><div><h1>' + title + '</h1><p>' + description + '</p></div><div class="actions">' + actions + '</div></div>';
}
function datasetBar() {
  const d = state.data;
  return '<div class="dataset-bar"><div>' + icon('file') + '<span class="dataset-name">' + esc(d.name) + '</span><span class="tag demo">' + (d.synthetic ? 'SYNTHETIC DATA' : 'UPLOADED CSV') + '</span></div><span>' + utcDate(d.first_seen) + ' · All times UTC</span></div>';
}
function metrics() {
  const d = state.data, top = ['Critical','High','Medium','Low'].find(s => d.severity_counts[s]) || 'None';
  const card = (label,value,foot,glyph,cls = '') => '<div class="metric"><div class="metric-head"><span>' + label + '</span><span class="metric-icon ' + (cls ? 'red' : '') + '">' + icon(glyph) + '</span></div><div class="metric-value ' + cls + '">' + value + '</div><div class="metric-foot">' + foot + '</div></div>';
  return '<div class="metrics">' + card('Events analyzed',fmt(d.events_analyzed),'Validated network records','activity') + card('Alerts generated',fmt(d.alerts_generated),'Across <strong>' + Object.keys(d.alert_type_counts).length + '</strong> detection types','shield') + card('Highest priority',top,'Priority, not proof of compromise','alert','word '+top.toLowerCase()) + card('Detection rules',state.rules.length,'Transparent, rule-based checks','sliders') + '</div>';
}

function alertTable(alerts) {
  if(!alerts.length)return '<div class="empty"><h3>No matching alerts</h3><p>Try another filter, or load the sample data.</p></div>';
  return '<div class="table-wrap"><table><thead><tr><th>Priority</th><th>Finding / case</th><th>Source IP</th><th>Events</th><th>Last seen · UTC</th><th>Review</th><th>Explain</th></tr></thead><tbody>'+
    alerts.map(a=>'<tr><td>'+badge(a.severity)+'</td><td><button class="finding" data-open="'+esc(a.alert_id)+'">'+esc(a.alert_type)+'</button><span class="finding-id mono">'+esc(a.case_id)+'</span></td>'+
      '<td class="mono">'+esc(a.source_ip)+'</td><td>'+a.event_count+'</td><td class="mono">'+utcTime(a.last_seen)+'</td><td><span class="status" data-status="'+esc(review(a.alert_id).status)+'">'+esc(review(a.alert_id).status)+'</span></td>'+
      '<td><button class="reasoning-button" data-open="'+esc(a.alert_id)+'"'+tip("See the evidence, trigger, alternatives, and suggested checks")+'>'+icon("spark")+'Reasoning</button></td></tr>').join('')+'</tbody></table></div>';
}
function overview() {return silcOverview();}
function filteredAlerts() {
  const q=state.query.toLowerCase();
  return state.data.alerts.filter(a=>
    (state.severity==="all"||a.severity===state.severity)&&
    (state.status==="all"||review(a.alert_id).status===state.status)&&
    (state.type==="all"||a.alert_type===state.type)&&
    (state.confidence==="all"||a.detection_confidence===state.confidence)&&
    (state.aiConfidence==="all"||(reviewExplanation(a.alert_id)?.prediction_confidence||"Not assessed")===state.aiConfidence)&&
    (!state.bucket||(new Date(a.first_seen)>=new Date(state.bucket)&&new Date(a.first_seen)<new Date(new Date(state.bucket).getTime()+600000)))&&
    [a.alert_id,a.case_id,a.alert_type,a.source_ip,a.destination_ip,a.evidence].some(v=>String(v||"").toLowerCase().includes(q)));
}
function queueContent() {
  const all=filteredAlerts(), pages=Math.max(1,Math.ceil(all.length/10));state.page=Math.min(state.page,pages);
  return alertTable(all.slice((state.page-1)*10,state.page*10))+'<div class="table-foot"><span>'+all.length+' matching alerts · Page '+state.page+' of '+pages+'</span><div class="actions"><button class="btn" data-action="prev" '+(state.page<=1?'disabled':'')+'>Previous</button><button class="btn" data-action="next" '+(state.page>=pages?'disabled':'')+'>Next</button></div></div>';
}
function queue() {
  return heading("Alert queue","Search findings, compare confidence labels, and open their Reasoning tab.",button("Export report","export","","download"))+datasetBar()+
    (state.data.alerts_truncated?'<div class="notice caution">The first 500 alerts are displayed and filtered here. Dashboard totals include all findings; Log explorer searches the full dataset.</div>':'')+
    '<section class="panel"><div class="filters"><div class="field search-field"><label for="alert-search">Search findings</label><div class="search-wrap">'+icon("search")+'<input id="alert-search" type="search" placeholder="IP, finding, case or alert ID…" value="'+esc(state.query)+'"></div></div>'+
    '<div class="field"><label for="severity-filter">Severity</label><select id="severity-filter">'+options(["all","Critical","High","Medium","Low"],state.severity)+'</select></div>'+
    '<div class="field"><label for="status-filter">Review status</label><select id="status-filter">'+options(["all",...REVIEW_STATUSES],state.status)+'</select></div>'+button("Reset","clear")+'</div>'+
    extraQueueFilters()+'<div id="queue-content">'+queueContent()+'</div></section>';
}
function uploadView() {
  return heading('Analyze network logs','Start with the sample, then try your own sanitized CSV.')+
    '<div class="section-grid"><section class="panel"><div class="panel-head"><h2>Import a dataset</h2><span class="tag">CSV ONLY</span></div><div class="dropzone" id="dropzone"><div class="upload-symbol">'+icon('upload')+'</div><h2>Drop your network logs here</h2><p>Up to 5 MB and 20,000 rows. Data stays in this local process unless you explicitly request a cloud AI briefing.</p><input type="file" id="file-input" accept=".csv,text/csv" hidden><button class="btn primary" data-action="choose-file" '+(state.uploadBusy?'disabled':'')+'>'+(state.uploadBusy?'Analyzing…':'Choose CSV file')+'</button><p class="small" style="margin-bottom:0">Or drag a CSV into this area</p></div><div class="file-result" id="upload-result" aria-live="polite"></div><div class="panel-pad" style="border-top:1px solid var(--line)"><h3>Just exploring?</h3><p class="muted small" style="margin:8px 0 17px">The included lab contains 11,000 synthetic events and five seeded threat patterns.</p><div class="actions">'+button('Load sample data','sample','soft','activity')+'<a class="btn" href="/api/sample.csv" download>Download sample CSV</a></div></div></section><aside><div class="notice caution"><strong>Use synthetic or sanitized logs.</strong> Do not upload employer data, passwords, tokens, or personal information.</div><section class="panel panel-pad"><h2>What happens to your file?</h2><ol class="list-clean"><li><span class="number">1</span><div>Validate<small>Check columns, timestamps, IP addresses, ports and unique event IDs.</small></div></li><li><span class="number">2</span><div>Detect<small>Run five transparent security checks. No AI is required.</small></div></li><li><span class="number">3</span><div>Investigate<small>Prioritize findings and open their matching log evidence.</small></div></li></ol><p class="muted small" style="margin-top:22px">Uploads expire after one hour, a restart, or more than three uploaded datasets. No uploaded CSV is saved to disk by this app.</p></section><section class="panel panel-pad" style="margin-top:20px"><h3>Required column names</h3><p class="schema" style="margin-top:12px">'+['event_id','timestamp','source_ip','destination_ip','destination_port','protocol','tcp_flags','username','auth_result','dns_query','http_status','redirect_domain'].map(c=>'<code>'+c+'</code>').join(' ')+'</p><p class="muted small" style="margin-top:13px">Use the downloaded sample as your template. Timestamps need a timezone, such as 2026-09-01T08:00:00+00:00.</p></section></aside></div>';
}
function rulesView() {
  return heading('Detection rules','Understand what triggers an alert, and what the rule cannot prove.')+
    '<div class="notice">Scores are fixed review priorities: Critical 95, High 75, Medium 50, Low 25. They are not confidence percentages. Time-based rules use fixed UTC buckets, not sliding windows.</div><div class="rule-grid">'+state.rules.map(r=>'<article class="panel rule-card"><div class="rule-top"><span class="rule-id">'+esc(r.id)+'</span>'+badge(r.severity)+'</div><h2>'+esc(r.title)+'</h2><p>'+esc(r.why)+'</p><div class="rule-logic"><strong>Trigger:</strong> '+esc(r.logic)+'</div><details><summary>False positives & investigation guidance</summary><p><strong>Possible benign cause:</strong> '+esc(r.false_positive)+'</p><p><strong>Next check:</strong> '+esc(r.next_check)+'</p><p><strong>Limitation:</strong> '+esc(r.limit)+'</p>'+(r.indicators?'<p>'+r.indicators.map(v=>'<code>'+esc(v)+'</code>').join('<br>')+'</p>':'')+'</details></article>').join('')+'</div>';
}
function briefingView() {
  const provider=state.providers.find(p=>p.id===state.provider);
  const available=knownAlerts();
  const ids=[...new Map([...available.filter(a=>state.selected.has(a.alert_id)),...state.data.alerts].map(a=>[a.alert_id,a])).values()].slice(0,100);
  const output=briefOutput();
  return heading('AI briefing','Turn selected findings into a draft you can question and verify.',button('Export report','export','','download'))+datasetBar()+
    '<div class="brief-layout"><section class="panel brief-controls"><h2>Build your briefing</h2><div class="field"><label for="provider-select">Analysis provider</label><select id="provider-select">'+state.providers.map(p=>'<option value="'+p.id+'" '+(p.id===state.provider?'selected':'')+' '+(!p.configured?'disabled':'')+'>'+esc(p.name)+(p.configured?'':' · setup needed')+'</option>').join('')+'</select></div><p class="muted small">'+(provider?.cloud?'Selected alert summaries will leave this computer. Never send sensitive logs.':state.provider==='ollama'?'Local model; requires Ollama running on this computer. Configuration is not a connection test.':'No model, key, or API bill. This produces a deterministic evidence summary, not an AI response.')+'</p><div class="actions" style="margin-top:15px"><strong class="small">Select up to 10 alerts</strong><button class="text-btn" data-action="select-top">Select top 5</button></div><p class="muted small">Showing up to 100 findings, with your selected cases first. You can also open a finding and choose Explain with a model.</p><div class="alert-picker">'+(ids.length?ids.slice(0,100).map(a=>'<label><input type="checkbox" data-select-alert="'+esc(a.alert_id)+'" '+(state.selected.has(a.alert_id)?'checked':'')+'><span>'+esc(a.alert_type)+'<small>'+esc(a.source_ip)+' · '+esc(a.severity)+' · '+esc(a.alert_id)+'</small></span></label>').join(''):'<p class="muted small">No alerts in this dataset.</p>')+'</div>'+(provider?.cloud?'<label class="checkrow"><input type="checkbox" id="cloud-consent"><span>I authorize sending the selected alert evidence, including IP addresses and indicators, to '+esc(provider.name)+'.</span></label>':'')+'<button class="btn primary full-width" id="generate-brief" data-action="generate" '+(state.aiBusy?'disabled':'')+'>'+(state.aiBusy?'<span class="spinner"></span> Generating…':icon('spark')+' Generate briefing')+'</button><p class="muted small" style="margin-top:12px">AI cannot change rules, block traffic, or execute commands. <a href="#guide">Connection setup →</a></p></section><section class="panel"><div class="panel-head"><h2>Analyst briefing</h2><span class="tag">HUMAN REVIEW</span></div><div class="brief-result" id="brief-result">'+output+'</div></section></div>';
}
function guideView() {
  return heading('Project guide','Understand it, personalize it, then demonstrate it with confidence.')+
    '<div class="guide-grid"><article class="panel guide-content"><h2>What this project actually does</h2><p>SILC is a defensive log-analysis lab. It accepts structured network events, checks them against five Python rules, and links each alert to the records that triggered it. The browser helps a human analyst investigate and document a decision.</p><p>It does not capture live traffic, train a machine-learning model, perform RAG, or automatically stop attacks.</p><h2>Reasoning and confidence</h2><p>Each finding opens with Reasoning: its observations, rule trigger, dataset comparison, missing telemetry, alternatives and ATT&amp;CK reference. AI explanations have their own Reasoning tabs and evidence links. Prediction confidence is a model self-assessment, not a measured probability. Hypothetical attack stages are labeled separately from observed records.</p><p>Use Log explorer to search the full dataset. Hover or focus chart bars for details; click to filter. Saved assessments stay in this browser for this dataset. AI results stay in this session, so export before reloading.</p><h2>A 3-minute recruiter demo</h2><ol class="list-clean"><li><span class="number">1</span><div>Show the overview<small>Explain that the 11,000 events are synthetic, reproducible, and safe to share.</small></div></li><li><span class="number">2</span><div>Investigate the SYN alert<small>Open its 85 matching records. Explain that volume alone does not prove an outage.</small></div></li><li><span class="number">3</span><div>Write your assessment<small>Mark it Investigating. Note that you would check handshake completion and service health.</small></div></li><li><span class="number">4</span><div>Generate a briefing and export<small>Distinguish rule-based evidence from AI interpretation, then show the report.</small></div></li></ol><h2>Explain SILC to a recruiter</h2><blockquote>“SILC is my cybersecurity investigation project. It connects Python detection rules to an interactive evidence workspace. Every finding has a Reasoning tab, and optional AI adds an evidence-linked interpretation. An analyst checks the evidence, records a decision, and exports the case.”</blockquote><p>Walk through one finding from its raw records to your saved assessment. Explain why the evidence supports a rule match and what you would need before confirming an incident.</p><h2>Make it yours before publishing</h2><ul><li>Change a rule threshold and document how the alert count changes.</li><li>Add one benign test case that should not trigger an alert.</li><li>Write an investigation note in your own words and export it.</li><li>Personalize one frontend component, then commit the change to GitHub.</li></ul><h2>Interview questions worth practicing</h2><details><summary>Why use rules as well as an LLM?</summary><p>Rules provide repeatable, inspectable evidence. The optional LLM writes a draft explanation; it does not decide what is malicious. A model can hallucinate or misread the context.</p></details><details><summary>How are false positives handled?</summary><p>A rule match starts an investigation. Verify authorized scanners, baseline traffic, user behavior, and service health. The lab lets you mark an alert benign and record your reasoning.</p></details><details><summary>What does a score of 95 mean?</summary><p>It is a fixed Critical priority chosen for this lab, not 95% confidence. The model did not calculate it.</p></details><details><summary>What would you improve next?</summary><p>Add sliding time windows, realistic labeled data, measured precision and recall, server-backed case storage, and authenticated deployment. Explain why each would improve this specific lab.</p></details></article><aside><section class="panel guide-content"><h2>Start the project on a Mac</h2><p>Open Terminal in the extracted project folder. Python 3.11, 3.12 or 3.13 is required.</p><div class="codeblock">bash start.sh</div><p>The browser opens when the app is ready. If it does not, use the address printed in Terminal. Keep Terminal open. Press Control+C there to stop the app.</p><h2>Connect local Ollama</h2><p>Install and open <a href="https://ollama.com" target="_blank" rel="noreferrer">Ollama</a>, then run:</p><div class="codeblock">ollama pull gemma3:4b</div><p>Select Ollama under AI briefing. Your Mac performs the processing; speed depends on available memory and the model.</p><h2>Use a cloud model</h2><p>Copy <code>.env.example</code> to <code>.env</code>. Set <code>ALLOW_CLOUD_AI=true</code>, your provider key, and a current model ID from that account. Restart SILC.</p><p>Only configured providers become selectable. API access, costs and quotas are separate provider settings. Do not assume a chat subscription includes API credit.</p><h2>Keep it private</h2><p>Never commit <code>.env</code>, API keys, real logs, or sensitive reports. This local lab has no user accounts and must not be exposed directly to the internet.</p></section><section class="panel guide-content" style="margin-top:20px"><h2>Where to look in the code</h2><p><code>frontend/</code><br>Layout, styling, buttons, filters and report export.</p><p><code>src/validation.py</code><br>CSV checks and normalization.</p><p><code>src/detections.py</code><br>Evidence-backed security rules.</p><p><code>src/api.py</code><br>Frontend-to-backend connection.</p><p><code>src/ai_providers.py</code><br>Optional AI connections and safe errors.</p><p><code>tests/</code><br>Reproducible checks.</p></section></aside></div>';
}
function render() {
  state.view=Object.prototype.hasOwnProperty.call(titles,location.hash.slice(1))?location.hash.slice(1):'overview';
  $('#crumb').textContent=titles[state.view];
  document.querySelectorAll('[data-nav]').forEach(el=>{el.classList.toggle('active',el.dataset.nav===state.view);if(el.dataset.nav===state.view)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});
  if(!state.data)return;
  $('#view').innerHTML=({overview,alerts:queue,logs:logsView,upload:uploadView,briefing:briefingView,rules:rulesView,guide:guideView}[state.view])();
  $('#view').setAttribute('aria-busy','false');
  $('#nav-count').textContent=state.data.alerts_generated;
  if(state.view==='upload')bindDropzone();
  if(state.view==='logs')loadLogs();
}
function navigate(view){if(location.hash==='#'+view)render();else location.hash=view;}
function bindDropzone() {
  const drop=$('#dropzone');
  ['dragover','dragenter'].forEach(type=>drop.addEventListener(type,e=>{e.preventDefault();drop.classList.add('dragging');}));
  ['dragleave','drop'].forEach(type=>drop.addEventListener(type,e=>{e.preventDefault();drop.classList.remove('dragging');}));
  drop.addEventListener('drop',e=>{if(e.dataTransfer.files[0])uploadFile(e.dataTransfer.files[0]);});
}
async function uploadFile(file) {
  if(state.uploadBusy)return;
  const feedback=$('#upload-result');
  if(!file.name.toLowerCase().endsWith('.csv')||file.size>5*1024*1024){feedback.innerHTML='<div class="notice error">Choose a CSV no larger than 5 MB.</div>';return;}
  state.uploadBusy=true;render();$('#upload-result').innerHTML='<div class="notice"><span class="spinner"></span> Validating and analyzing '+esc(file.name)+'…</div>';
  try {
    const body=new FormData();body.append('file',file);
    const data=await api('/api/analyze-file',{method:'POST',body});setDataset(data);navigate('overview');toast('Analysis complete. '+data.alerts_generated+' alerts generated.');
  } catch(error) {if($('#upload-result'))$('#upload-result').innerHTML='<div class="notice error" role="alert">'+esc(error.message)+'</div>';else toast(error.message);}
  finally {state.uploadBusy=false;const b=$('[data-action="choose-file"]');if(b){b.disabled=false;b.textContent='Choose CSV file';}}
}
function setDataset(data){
  caseRequest++;state.data=data;state.query="";state.severity="all";state.status="all";state.type="all";state.confidence="all";state.aiConfidence="all";
  state.bucket=null;state.page=1;state.timelineStart=0;state.selected=new Set(data.alerts.slice(0,5).map(a=>a.alert_id));state.brief=null;
  state.contexts.clear();state.detailContext=null;state.detailId=null;state.logQuery="";state.logProtocol="all";state.logSeverity="all";state.logLinked=false;state.logOffset=0;
  if($("#detail").open)$("#detail").close();
}
async function loadSample(){try{setDataset(await api('/api/analysis'));navigate('overview');toast('Synthetic lab loaded.');}catch(e){toast(e.message);}}
async function openDetail(id) {return openCase(id);}
async function generateBrief() {
  if(state.aiBusy)return;
  if(!state.selected.size){toast('Select at least one alert.');return;}
  const provider=state.providers.find(p=>p.id===state.provider), consent=!!$('#cloud-consent')?.checked;
  if(provider?.cloud&&!consent){toast('Confirm cloud data sharing before generating.');return;}
  const analysisId=state.data.analysis_id;
  state.aiBusy=true;state.brief=null;render();
  try{const result=await api('/api/ai-summary',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({analysis_id:analysisId,alert_ids:[...state.selected],provider:state.provider,consent_to_cloud:consent})});
    if(state.data.analysis_id===analysisId){state.brief=result;ingestBrief(result);if($('#detail').open){captureDraft();renderCase();}toast('Briefing ready. Review it against the evidence.');}
  }catch(e){if(state.view==='briefing')$('#brief-result').innerHTML='<div class="notice error" role="alert">'+esc(e.message)+'</div>';toast('Briefing unavailable. The detection results are unchanged.');}
  finally{state.aiBusy=false;if(state.view==='briefing'&&state.brief)render();else{const b=$('#generate-brief');if(b){b.disabled=false;b.innerHTML=icon('spark')+' Generate briefing';}}}
}
async function exportReport() {
  try {
    const analysisId=state.data.analysis_id;
    const response=await fetch('/api/report?analysis_id='+encodeURIComponent(analysisId));
    if(!response.ok)throw new Error('Report unavailable. The upload may have expired; load it again.');
    let report=await response.text();
    if(state.data.analysis_id!==analysisId){toast('The dataset changed. Export the current dataset again.');return;}
    report+='\n\n## Analyst assessments (entered by the user)\n';
    for(const a of knownAlerts()){const r=review(a.alert_id);if(r.note||r.status!=='New')report+='\n### '+a.alert_id+'\nStatus: '+r.status+'\n\n'+r.note+'\n';}
    if(state.brief&&state.brief.analysis_id===state.data.analysis_id)report+='\n## '+(state.brief.is_ai?'AI-generated draft':'Offline rule-template briefing')+'\nProvider: '+state.brief.provider+'\n\n'+state.brief.summary+'\n\n'+state.brief.disclaimer+'\n';
    report+=explanationReport();
    report+='\n\nSILC is a local cybersecurity portfolio lab. Findings require analyst review.\n';
    const url=URL.createObjectURL(new Blob([report],{type:'text/markdown;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='SILC-Incident-Report.md';a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);toast('Report exported with your saved assessments.');
  }catch(e){toast(e.message);}
}
document.addEventListener('click',e=>{
  if(workspaceClick(e))return;
  const open=e.target.closest('[data-open]');if(open){openDetail(open.dataset.open);return;}
  const action=e.target.closest('[data-action]')?.dataset.action;if(!action)return;
  if(action==='upload')navigate('upload');
  if(action==='export')exportReport();
  if(action==='sample')loadSample();
  if(action==='choose-file')$('#file-input').click();
  if(action==='generate')generateBrief();
  if(action==='select-top'){state.selected=new Set(state.data.alerts.slice(0,5).map(a=>a.alert_id));render();}
  if(action==='prev'||action==='next'){state.page+=action==='prev'?-1:1;$('#queue-content').innerHTML=queueContent();}
  if(action==='clear'){filterBy('severity','all');}
  if(action==='brief-alert'){state.selected=new Set([state.detailId]);$('#detail').close();navigate('briefing');}
  if(action==='retry')initialize();
});
document.addEventListener('input',e=>{if(workspaceInput(e))return;if(e.target.id==='alert-search'){state.query=e.target.value;state.page=1;$('#queue-content').innerHTML=queueContent();}});
document.addEventListener('change',e=>{
  if(workspaceChange(e))return;
  if(e.target.id==='severity-filter'||e.target.id==='status-filter'){state[e.target.id==='severity-filter'?'severity':'status']=e.target.value;state.page=1;$('#queue-content').innerHTML=queueContent();}
  if(e.target.id==='file-input'&&e.target.files[0])uploadFile(e.target.files[0]);
  if(e.target.id==='provider-select'){state.provider=e.target.value;state.brief=null;render();}
  if(e.target.dataset.selectAlert){const id=e.target.dataset.selectAlert;if(e.target.checked){if(state.selected.size>=10){e.target.checked=false;toast('Choose up to 10 alerts per briefing.');}else state.selected.add(id);}else state.selected.delete(id);}
});
document.addEventListener('submit',e=>{if(e.target.id==='review-form'){e.preventDefault();recordAssessment();}});
$('#close-detail').addEventListener('click',()=>{captureDraft();$('#detail').close();});
$('#detail').addEventListener('cancel',captureDraft);
$('#help-button').addEventListener('click',()=>navigate('guide'));
window.addEventListener('hashchange',()=>{render();$('#main').focus({preventScroll:true});window.scrollTo(0,0);});
async function initialize() {
  initWorkspace();
  $('#global-error').hidden=true;
  try {const [data,rules,providers]=await Promise.all([api('/api/analysis'),api('/api/rules'),api('/api/providers')]);state.rules=rules;state.providers=providers;setDataset(data);$('#connection').textContent='Local lab connected';render();}
  catch(e){$('#connection').textContent='Backend unavailable';$('#global-error').textContent=e.message;$('#global-error').hidden=false;$('#view').innerHTML='<div class="empty"><h2>Start the local app first</h2><p style="margin:12px 0">Run <code>bash start.sh</code> in the extracted project folder, then use the address printed in Terminal.</p>'+button('Try again','retry','primary')+'</div>';}
}
initialize();
