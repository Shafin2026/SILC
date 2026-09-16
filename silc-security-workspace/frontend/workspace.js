/* SILC investigation views. Plain JavaScript; no build step or chart dependency.
   app.js owns API access, shared helpers and application state. */
"use strict";

const CASE_TABS = {reasoning:"Reasoning",evidence:"Evidence",connections:"Connections",assessment:"Assessment"};
const REVIEW_STATUSES = ["New","Investigating","Needs escalation","Benign"];
const CONFIDENCE_LEVELS = ["Low","Moderate","High","Not assessed"];
const REVIEW_STORAGE = "silc-reviews-v3";
let workspaceStarted = false;
let logRequest = 0;
let caseRequest = 0;

function tip(text) {return ' data-tooltip="' + esc(text) + '"';}
function fullTime(time) {return utcDate(time) + ' ' + utcTime(time) + ' UTC';}
function listText(items) {return '<ul class="explain-list">'+items.map(s=>'<li>'+esc(s)+'</li>').join('')+'</ul>';}
function options(values, selected, allLabel="All") {
  return values.map(value=>'<option value="'+esc(value)+'"'+(value===selected?' selected':'')+'>'+esc(value==="all"?allLabel:value)+'</option>').join('');
}
function reviewExplanation(id) {return state.explanations[noteKey(id)] || null;}
function knownAlerts() {
  return [...new Map([...state.data.alerts,...[...state.contexts.values()].map(c=>c.alert)].map(a=>[a.alert_id,a])).values()];
}
function remainingReviews() {return state.data.alerts.filter(a=>["New","Investigating"].includes(review(a.alert_id).status)).length;}

function initWorkspace() {
  if (workspaceStarted) return;
  workspaceStarted = true;
  try {
    const saved = JSON.parse(localStorage.getItem(REVIEW_STORAGE) || "null");
    if (saved?.version === 1 && saved.notes && typeof saved.notes === "object") {
      for (const [key,value] of Object.entries(saved.notes).slice(-1000)) {
        if (!/^[a-f0-9]{64}:ALT-[A-F0-9]{10}$/.test(key) || !value || !REVIEW_STATUSES.includes(value.status)) continue;
        state.notes[key] = {status:value.status,note:typeof value.note==="string"?value.note.slice(0,4000):"",
          checks:Array.isArray(value.checks)?value.checks.filter(s=>["verify","collect","decide"].includes(s)):[],
          updated:typeof value.updated==="string"?value.updated:""};
      }
      state.audit = Array.isArray(saved.audit) ? saved.audit.filter(r=>r && typeof r.key==="string" && typeof r.action==="string" && typeof r.time==="string").slice(-500) : [];
    }
  } catch (_) {state.storageNotice="Saved reviews could not be loaded. You can still investigate and export.";}
  wireWorkspaceInteractions();
}
function saveReviews() {
  const entries = Object.entries(state.notes).slice(-1000);
  state.notes = Object.assign(Object.create(null),Object.fromEntries(entries));
  try {
    localStorage.setItem(REVIEW_STORAGE,JSON.stringify({version:1,notes:state.notes,audit:state.audit.slice(-500)}));
    return true;
  } catch (_) {toast("Browser storage is unavailable. Export your report to keep your assessment.");return false;}
}
function recordAssessment() {
  if (!state.detailId) return;
  const status=$("#review-status").value, note=$("#analyst-note").value.slice(0,4000);
  const checks=[...document.querySelectorAll("[data-check-step]:checked")].map(el=>el.dataset.checkStep);
  const key=noteKey(state.detailId), time=new Date().toISOString();
  state.notes[key]={status,note,checks,updated:time};
  delete state.drafts[key];
  state.audit.push({key,time,action:"Analyst saved "+status+"; completed checks: "+(checks.join(", ")||"none")});
  state.audit=state.audit.slice(-500);
  if (saveReviews()) toast("Assessment saved in this browser. No response action was executed.");
  render();
  renderCase();
}
function ingestBrief(result) {
  const generated=new Date().toISOString();
  for (const explanation of result.explanations || []) {
    state.explanations[noteKey(explanation.alert_id)]={...explanation,is_ai:result.is_ai,provider:result.provider,model:result.model,
      confidence_note:result.confidence_note,generated};
  }
}
function filterBy(kind,value) {
  state.query="";state.severity="all";state.status="all";state.type="all";state.confidence="all";state.aiConfidence="all";state.bucket=null;state.page=1;
  state[kind]=value;navigate("alerts");
}

/* Hover information is also available on focus. Every bar is a real button. */
function breakdown(data, kind, unit="alerts") {
  const entries=Object.entries(data), max=Math.max(1,...entries.map(([,v])=>v));
  return '<div class="breakdown">'+entries.map(([label,value],i)=>
    '<button class="breakdown-row" data-filter-kind="'+kind+'" data-filter-value="'+esc(label)+'"'+tip(label+"\n"+fmt(value)+" "+unit+"\nClick to investigate")+'>'+
    '<span class="breakdown-label">'+esc(label)+'</span><strong>'+fmt(value)+'</strong>'+
    '<span class="breakdown-track"><span class="chart-color-'+(i%5)+'" style="width:'+(value/max*100)+'%"></span></span></button>').join('')+'</div>';
}
function severityChart() {
  const d=state.data, total=d.alerts_generated, colors={Critical:"#b32148",High:"#b77721",Medium:"#4561ca",Low:"#137457"};
  let offset=0;
  const segments=Object.entries(d.severity_counts).map(([severity,n])=>{
    if(!n)return '';
    const length=total?n/total*100:0, part='<circle class="donut-segment" role="button" tabindex="0" data-filter-kind="severity" data-filter-value="'+severity+'" aria-label="'+severity+': '+n+' alerts. Filter this severity."'+tip(severity+"\n"+n+" alerts\nClick to filter")+' cx="60" cy="60" r="45" fill="none" stroke="'+colors[severity]+'" stroke-width="13" pathLength="100" stroke-dasharray="'+length+' '+(100-length)+'" stroke-dashoffset="'+(-offset)+'" transform="rotate(-90 60 60)"/>';
    offset+=length;return part;
  }).join('');
  return '<div class="severity-chart"><svg viewBox="0 0 120 120" role="group" aria-label="'+total+' alerts by severity. Select a segment or use the labeled buttons."><circle cx="60" cy="60" r="45" fill="none" stroke="#e9edf6" stroke-width="13"/>'+segments+
    '<text x="60" y="58" text-anchor="middle" class="donut-value">'+fmt(total)+'</text><text x="60" y="76" text-anchor="middle" class="donut-label">alerts</text></svg>'+
    '<div class="severity-legend">'+Object.entries(d.severity_counts).map(([s,n])=>'<button data-filter-kind="severity" data-filter-value="'+s+'"'+tip(s+"\n"+n+" alerts\nClick to filter")+'><span class="dot-label '+s.toLowerCase()+'"><i class="square"></i>'+s+'</span><strong>'+n+'</strong></button>').join('')+'</div></div>';
}
function interactiveTimeline(plotOnly=false) {
  const buckets=state.data.timeline, visible=36;
  state.timelineStart=Math.max(0,Math.min(state.timelineStart,Math.max(0,buckets.length-visible)));
  const segment=buckets.slice(state.timelineStart,state.timelineStart+visible), max=Math.max(1,...segment.map(b=>b.events));
  const plot='<div class="timeline-label"><span>Events per 10 minutes</span><span>Peak in view: '+fmt(max)+'</span></div>'+
    '<div class="timeline-bars" aria-label="Interactive event timeline">'+segment.map(b=>
      '<button class="timeline-bar'+(b.alerts?' has-alerts':'')+'" data-bucket="'+esc(b.time)+'" style="--bar-height:'+Math.max(2,b.events/max*100)+'%"'+
      tip(fullTime(b.time)+"\n"+fmt(b.events)+" network events\n"+b.alerts+" findings first observed\nClick to see these findings")+' aria-label="'+esc(fullTime(b.time)+": "+b.events+" events; "+b.alerts+" findings. Filter this interval.")+'>'+
      '<span class="bar-fill"></span>'+(b.alerts?'<span class="bar-marker">'+b.alerts+'</span>':'')+'</button>').join('')+'</div>'+
    '<div class="timeline-axis"><span>'+fullTime(segment[0].time)+'</span><span>'+fullTime(segment[segment.length-1].time)+'</span></div>';
  if(plotOnly)return plot;
  return '<div class="timeline-interactive"><div id="timeline-plot">'+plot+'</div>'+
    (buckets.length>visible?'<label class="timeline-scrubber">Move through the dataset<input id="timeline-window" type="range" min="0" max="'+(buckets.length-visible)+'" value="'+state.timelineStart+'"></label>':'')+
    '<p class="chart-hint">Hover or focus a bar for details. Pink markers count findings first observed in that interval.</p></div>';
}
function silcOverview() {
  const mode='<div class="mode-switch" aria-label="Dashboard detail level"><button data-mode="analyst" aria-pressed="'+(state.mode==="analyst")+'">Analyst</button><button data-mode="executive" aria-pressed="'+(state.mode==="executive")+'">Executive</button></div>';
  const headingHtml=heading("Understand the signal.","Security Intelligence & Log Correlation",mode+button("Export report","export","","download")+button("Analyze logs","upload","primary","upload"));
  const overviewTop='<div class="workspace-intro"><div><span class="eyebrow">SILC / INVESTIGATION WORKSPACE</span><h2>Evidence first. Your judgment next.</h2><p>Review findings, explore the context, and open Reasoning to understand every flag.</p></div><span class="human-pill">'+icon("check")+'Human decisions always</span></div>';
  const executive=state.mode==="executive"?'<section class="panel executive-card"><div><span class="eyebrow">EXECUTIVE BRIEF</span><h2>'+state.data.alerts_generated+' findings need an analyst’s judgment.</h2><p>'+remainingReviews()+' displayed findings are new or under investigation. Business impact, compromise and service availability are not established by the CSV.</p></div><div class="executive-stat"><strong>'+fmt(state.data.linked_events)+'</strong><span>records linked to rule findings</span></div></section>':'';
  return headingHtml+overviewTop+datasetBar()+metrics()+executive+
    '<div class="overview-grid"><section class="panel"><div class="panel-head"><div><h2>Network activity</h2><p class="panel-sub">Explore an interval to narrow your investigation</p></div><span class="tag">INTERACTIVE</span></div><div id="timeline-content">'+interactiveTimeline()+'</div></section>'+
    '<section class="panel"><div class="panel-head"><div><h2>Review priorities</h2><p class="panel-sub">Choose a severity to open the queue</p></div></div>'+severityChart()+'<p class="priority-note">Priority is not a confidence percentage.</p></section></div>'+
    (state.mode==="analyst"?'<div class="analytics-grid"><section class="panel"><div class="panel-head"><h2>Detection patterns</h2></div>'+breakdown(state.data.alert_type_counts,"type")+'</section>'+
    '<section class="panel"><div class="panel-head"><h2>Protocol mix</h2></div>'+breakdown(state.data.protocol_counts,"protocol","events")+'</section></div>':'')+
    '<section class="panel"><div class="panel-head table-title"><div><h2>Start an investigation</h2><p class="panel-sub">Every finding opens with its Reasoning tab</p></div><a href="#alerts" class="text-btn">View all findings →</a></div>'+alertTable(state.data.alerts.slice(0,5))+
    '<div class="table-foot"><span>Showing '+Math.min(5,state.data.alerts.length)+' of '+state.data.alerts_generated+' findings</span><a href="#logs">Explore raw logs →</a></div></section>';
}
function extraQueueFilters() {
  const types=["all",...Object.keys(state.data.alert_type_counts)];
  return '<div class="filters advanced-filters"><div class="field"><label for="type-filter">Detection type</label><select id="type-filter">'+options(types,state.type)+'</select></div>'+
    '<div class="field"><label for="confidence-filter">Detection confidence</label><select id="confidence-filter">'+options(["all","Pattern supported","Indicator only"],state.confidence)+'</select></div>'+
    '<div class="field"><label for="ai-confidence-filter">AI prediction confidence</label><select id="ai-confidence-filter">'+options(["all",...CONFIDENCE_LEVELS],state.aiConfidence)+'</select></div>'+
    '<p class="filter-note">Rule support and AI self-assessment are separate, uncalibrated labels.</p></div>'+
    (state.bucket?'<div class="active-filter">Findings first observed: '+fullTime(state.bucket)+' to '+utcTime(new Date(new Date(state.bucket).getTime()+600000))+' UTC '+button("Clear interval","clear-bucket")+'</div>':'');
}

/* Search the full validated dataset, not just the visible alert preview. */
function logsView() {
  return heading("Log explorer","Search the validated CSV and follow records into their linked findings.",button("Export report","export","","download"))+datasetBar()+
    '<section class="panel"><div class="filters"><div class="field search-field"><label for="log-search">Search records</label><input id="log-search" type="search" maxlength="128" placeholder="IP address, user, domain or event ID" value="'+esc(state.logQuery)+'"></div>'+
    '<div class="field"><label for="log-protocol">Protocol</label><select id="log-protocol">'+options(["all",...Object.keys(state.data.protocol_counts)],state.logProtocol)+'</select></div>'+
    '<div class="field"><label for="log-severity">Linked severity</label><select id="log-severity">'+options(["all","Critical","High","Medium","Low"],state.logSeverity)+'</select></div>'+
    '<label class="checkrow"><input type="checkbox" id="log-linked"'+(state.logLinked?' checked':'')+'>Linked records only</label>'+button("Reset","reset-logs")+'</div>'+
    '<div id="log-results" aria-live="polite"><div class="loading"><span class="spinner"></span>Loading records…</div></div></section>';
}
function eventTable(events, related=false) {
  if(!events.length)return '<div class="empty"><h3>No matching records</h3><p>Try a different search or filter.</p></div>';
  return '<div class="table-wrap"><table><thead><tr><th>Event</th><th>Time · UTC</th><th>Connection</th><th>Protocol / port</th><th>Signal</th><th>'+(related?'Context':'Finding')+'</th></tr></thead><tbody>'+
    events.map(e=>'<tr data-event-id="'+esc(e.event_id)+'"><td class="mono">'+esc(e.event_id)+'</td><td>'+esc(utcDate(e.timestamp))+'<span class="finding-id mono">'+utcTime(e.timestamp)+'</span></td>'+
      '<td class="mono">'+esc(e.source_ip)+'<span class="finding-id">to '+esc(e.destination_ip)+'</span></td><td>'+esc(e.protocol)+' / '+esc(e.destination_port)+'</td>'+
      '<td class="signal-cell">'+esc(e.auth_result||e.dns_query||e.redirect_domain||e.tcp_flags||"—")+'</td><td>'+
      (e.alert_ids?.length?e.alert_ids.map(id=>'<button class="text-btn" data-open="'+esc(id)+'">'+esc(id)+'</button>').join("<br>"):related?'Shared host / time':'No rule link')+'</td></tr>').join('')+'</tbody></table></div>';
}
async function loadLogs() {
  const request=++logRequest, analysisId=state.data.analysis_id;
  const params=new URLSearchParams({analysis_id:analysisId,q:state.logQuery,offset:String(state.logOffset),limit:"50"});
  if(state.logProtocol!=="all")params.set("protocol",state.logProtocol);
  if(state.logSeverity!=="all")params.set("severity",state.logSeverity);
  if(state.logLinked)params.set("linked_only","true");
  try {
    const result=await api("/api/events?"+params);
    if(request!==logRequest||state.view!=="logs"||state.data.analysis_id!==analysisId)return;
    state.logTotal=result.total;
    $("#log-results").innerHTML=eventTable(result.events)+'<div class="table-foot"><span>'+fmt(result.total)+' matching records · '+(result.total?result.offset+1:0)+'–'+Math.min(result.offset+50,result.total)+'</span><div class="actions">'+
      '<button class="btn" data-action="log-prev"'+(state.logOffset===0?' disabled':'')+'>Previous</button><button class="btn" data-action="log-next"'+(state.logOffset+50>=result.total?' disabled':'')+'>Next</button></div></div>';
  }catch(error){if(request===logRequest&&$("#log-results"))$("#log-results").innerHTML='<div class="notice error">'+esc(error.message)+'</div>';}
}
function goToLogs(ip="", protocol="all") {
  state.logQuery=ip;state.logProtocol=protocol;state.logSeverity="all";state.logLinked=false;state.logOffset=0;
  if($("#detail").open)$("#detail").close();
  navigate("logs");
}

/* Explanations returned by a provider must pass backend schema and citation checks. */
function explanationHtml(explanation) {
  if(!explanation)return '<div class="notice">No AI explanation has been generated for this finding. The rule reasoning remains available below.</div>';
  return '<section class="ai-explanation" data-explanation-alert="'+esc(explanation.alert_id)+'"><div class="actions"><span class="tag">'+(explanation.is_ai?'AI DRAFT · REVIEW REQUIRED':'OFFLINE TEMPLATE · NOT AI')+'</span><span class="muted small">'+esc(explanation.provider)+'</span></div>'+
    '<h3>'+esc(explanation.assessment)+'</h3><p>'+esc(explanation.rationale)+'</p>'+
    '<div class="citation-list"><strong>Evidence references</strong> '+explanation.evidence_ids.map(id=>'<button class="citation" data-evidence-id="'+esc(id)+'"'+tip("Show supporting record "+id)+'>'+esc(id)+'</button>').join(' ')+'</div>'+
    '<div class="explanation-columns"><div><h4>Possible alternatives</h4>'+listText(explanation.alternatives)+'</div><div><h4>Missing evidence</h4>'+listText(explanation.missing_evidence)+'</div></div>'+
    '<h4>Suggested next checks</h4><ol class="explain-list">'+explanation.next_steps.map(s=>'<li><strong>'+esc(s.action)+'</strong><br>'+esc(s.why)+'</li>').join('')+'</ol>'+
    '<div class="hypothesis-box"><span class="eyebrow">HYPOTHESIS · NOT OBSERVED</span><p>'+esc(explanation.hypothesis)+'</p><strong>AI prediction confidence: '+esc(explanation.prediction_confidence)+'</strong><p class="small">'+esc(explanation.confidence_note)+'</p></div></section>';
}
function comparisonHtml(b) {
  if(b.threshold==null)return '<div class="notice">'+esc(b.note)+'</div>';
  const values=[["Observed",b.observed],["Rule threshold",b.threshold]];
  if(b.available)values.push(["Earlier median",b.median]);
  const max=Math.max(1,...values.map(([,v])=>v));
  return '<div class="comparison-chart">'+values.map(([label,value],i)=>'<div class="comparison-row" tabindex="0"'+tip(label+": "+value+" "+b.unit+"\n"+b.note)+'><span>'+label+'</span><div><span class="chart-color-'+i+'" style="width:'+(value/max*100)+'%"></span></div><strong>'+value+'</strong></div>').join('')+'</div>'+
    '<p class="muted small">'+esc(b.unit)+' · '+esc(b.note)+'</p>';
}
function ruleReasoning(c) {
  const r=c.reasoning, x=reviewExplanation(c.alert.alert_id);
  return '<div class="reasoning-lead"><span class="eyebrow">WHY THIS FINDING EXISTS</span><h3>'+esc(r.observed)+'</h3><p>'+esc(r.why_flagged)+'</p><div class="rule-logic"><strong>Trigger:</strong> '+esc(r.rule_trigger)+'</div></div>'+
    '<div class="confidence-grid"><div><span>Detection confidence</span><strong>'+esc(r.detection_confidence)+'</strong><small>'+esc(r.confidence_note)+'</small></div>'+
    '<div><span>AI prediction confidence</span><strong>'+esc(x?.prediction_confidence||"Not assessed")+'</strong><small>'+(x?.is_ai?'Model self-assessment; uncalibrated, not a probability.':'No model prediction is available.')+'</small></div></div>'+
    '<section class="detail-section"><h3>Observed versus comparison</h3>'+comparisonHtml(r.comparison)+'</section>'+
    '<section class="detail-section"><h3>Evidence quality · '+esc(r.evidence_quality)+'</h3><p>'+r.evidence_available+' matching records are available; '+r.preview_shown+' appear in the evidence preview. This CSV is not the full incident context.</p><h4>Missing telemetry</h4>'+listText(r.missing_telemetry)+'</section>'+
    '<section class="detail-section"><h3>Possible false positives</h3>'+listText(r.false_positives)+'<h4>Limits of this rule</h4>'+listText(r.limitations)+'</section>'+
    '<section class="detail-section"><h3>MITRE ATT&CK reference</h3><a href="'+esc(r.technique.url)+'" target="_blank" rel="noreferrer">'+esc(r.technique.id+' · '+r.technique.name)+' ↗</a><p>'+esc(r.technique.basis)+'. This is an analyst reference, not an attribution or confirmation.</p></section>'+
    '<section class="detail-section"><h3>AI explanation</h3>'+explanationHtml(x)+'<div class="actions">'+button(x?"Generate another explanation":"Explain with a model","brief-alert","soft","spark")+'</div></section>';
}

function graphHtml(c) {
  const edges=c.graph.edges, hosts=[...new Set(edges.flatMap(e=>[e.source,e.target]))];
  const positions=new Map(hosts.map((host,i)=>{
    const angle=i*Math.PI*2/hosts.length-Math.PI/2;
    return [host,{x:250+Math.cos(angle)*172,y:165+Math.sin(angle)*118}];
  }));
  const lines=edges.map(e=>{
    const s=positions.get(e.source),t=positions.get(e.target);
    return '<path d="'+(e.source===e.target?'M'+s.x+','+s.y+' c-80,-80 80,-80 0,0':'M'+s.x+','+s.y+' L'+t.x+','+t.y)+'" class="graph-edge"'+tip(e.source+" → "+e.target+"\n"+e.events+" observed records")+'><title>'+esc(e.source+" to "+e.target+": "+e.events+" records")+'</title></path>';
  }).join('');
  const nodes=hosts.map((host,i)=>{
    const p=positions.get(host), count=edges.filter(e=>e.source===host||e.target===host).reduce((n,e)=>n+e.events,0);
    return '<g class="graph-node" role="button" tabindex="0" data-graph-ip="'+esc(host)+'" aria-label="'+esc("Explore logs for "+host)+'"'+tip(host+"\n"+count+" records across shown connections\nClick to explore logs")+'>'+
      '<circle cx="'+p.x+'" cy="'+p.y+'" r="19" class="graph-node-'+(i%3)+'"/><text x="'+p.x+'" y="'+(p.y+4)+'" text-anchor="middle" class="graph-node-number">'+(i+1)+'</text>'+
      '<text x="'+p.x+'" y="'+(p.y+38)+'" text-anchor="middle" class="graph-label">'+esc(host.length>22?host.slice(0,19)+"…":host)+'</text></g>';
  }).join('');
  return '<div class="evidence-graph"><svg viewBox="0 0 500 350" aria-label="Observed connection graph. Labeled nodes open the log explorer.">'+lines+nodes+'</svg></div>'+
    '<div class="graph-connections">'+edges.map(e=>'<button data-graph-ip="'+esc(e.source)+'"'+tip(e.events+" observed CSV records; shared hosts do not prove causation")+'><span class="mono">'+esc(e.source)+' → '+esc(e.target)+'</span><strong>'+fmt(e.events)+'</strong></button>').join('')+'</div>'+
    '<p class="muted small">Showing '+edges.length+' of '+c.graph.total_connections+' observed source/destination pairs in the correlation window. Lines show CSV connections, not an attack sequence.</p>';
}
function connectionsHtml(c) {
  const x=reviewExplanation(c.alert.alert_id);
  return '<section class="detail-section"><h3>Evidence graph</h3><p>'+esc(c.correlation_note)+'</p>'+graphHtml(c)+'</section>'+
    '<section class="detail-section"><h3>Observed and possible attack stages</h3><div class="attack-stages"><div class="observed-stage"><span class="tag">OBSERVED</span><h4>'+esc(c.attack_path[0].title)+'</h4><p>'+esc(c.attack_path[0].description)+'</p></div>'+
    '<div class="hypothesis-stage"><span class="tag">HYPOTHESIS · NOT OBSERVED</span><h4>'+esc(c.attack_path[1].title)+'</h4><p>'+esc(x?.hypothesis||c.attack_path[1].description)+'</p><small>'+(x?.is_ai?'AI prediction confidence: '+esc(x.prediction_confidence)+' · uncalibrated':esc(c.attack_path[1].source)+' · confidence not assessed')+'</small></div></div></section>'+
    '<section class="detail-section"><h3>Related findings</h3><p>Showing '+c.related_alerts.length+' of '+c.related_alerts_total+'. Association does not confirm a shared incident.</p>'+
    (c.related_alerts.length?c.related_alerts.map(a=>'<button class="related-card" data-open="'+esc(a.alert_id)+'"><span>'+badge(a.severity)+' '+esc(a.alert_type)+'</span><small>'+esc(a.source_ip)+' · '+esc(a.case_id)+'</small></button>').join(''):'<div class="notice">No other rule findings share this host/time window.</div>')+'</section>'+
    '<section class="detail-section"><h3>Surrounding records</h3><p>Showing '+c.related_events.length+' of '+c.related_events_total+' neighboring records, excluding the primary evidence.</p>'+eventTable(c.related_events,true)+'</section>';
}
function assessmentHtml(c) {
  const saved=state.drafts[noteKey(c.alert.alert_id)]||review(c.alert.alert_id);
  return '<form id="review-form" class="review-form"><div class="notice">Record your judgment and evidence checks. These controls save notes; they do not block traffic, change accounts or run commands.</div>'+
    '<h3>Guided investigation</h3>'+c.next_steps.map(s=>'<label class="check-step"><input type="checkbox" data-check-step="'+s.id+'"'+(saved.checks?.includes(s.id)?' checked':'')+'><span><strong>'+esc(s.title)+'</strong><small>'+esc(s.why)+'</small></span></label>').join('')+
    '<div class="field"><label for="review-status">Your disposition</label><select id="review-status">'+options(REVIEW_STATUSES,saved.status)+'</select></div>'+
    '<div class="field"><label for="analyst-note">Why did you choose this disposition?</label><textarea id="analyst-note" maxlength="4000" placeholder="Describe the evidence, uncertainty, and what you checked.">'+esc(saved.note)+'</textarea></div>'+
    '<div class="actions"><button type="submit" class="btn primary">Save assessment</button>'+button("Export case JSON","export-case")+'</div>'+
    '<p class="muted small">Saved in this browser for this dataset. Export before clearing browser data or changing localhost ports.</p></form>'+
    '<section class="detail-section"><h3>Review activity</h3><p>Local analyst activity recorded using your browser’s clock. This is an editable portfolio record, not a tamper-proof audit log.</p>'+
    '<ul class="audit-list">'+state.audit.filter(a=>a.key===noteKey(c.alert.alert_id)).slice(-20).reverse().map(a=>'<li><time>'+esc(a.time)+'</time><span>'+esc(a.action)+'</span></li>').join('')+'</ul></section>';
}
function renderCase() {
  const c=state.detailContext;if(!c)return;
  const a=c.alert, tab=state.detailTab;
  const content=tab==="reasoning"?ruleReasoning(c):tab==="connections"?connectionsHtml(c):tab==="assessment"?assessmentHtml(c):
    '<div class="detail-section"><h3>Matching log evidence</h3><p>'+c.evidence.length+' of '+a.event_count+' matching records shown. References link to these exact records.</p>'+eventTable(c.evidence)+'</div>';
  $("#detail-body").innerHTML='<div class="detail-heading">'+badge(a.severity)+'<span class="mono">'+esc(c.case_id)+'</span></div><h2 id="detail-title">'+esc(a.alert_type)+'</h2>'+
    '<p class="muted small">'+esc(a.alert_id)+' · '+fullTime(a.first_seen)+'</p><div class="case-tabs" role="tablist" aria-label="Investigation sections">'+Object.entries(CASE_TABS).map(([id,name])=>
    '<button role="tab" id="tab-'+id+'" aria-selected="'+(tab===id)+'" aria-controls="case-panel" tabindex="'+(tab===id?0:-1)+'" data-case-tab="'+id+'">'+name+'</button>').join('')+'</div>'+
    '<div id="case-panel" role="tabpanel" aria-labelledby="tab-'+tab+'">'+content+'</div>';
}
async function openCase(id) {
  const request=++caseRequest, analysisId=state.data.analysis_id, key=noteKey(id);
  state.detailId=id;state.detailTab="reasoning";state.detailContext=null;
  $("#detail-body").innerHTML='<h2 id="detail-title">Loading investigation</h2><div class="loading"><span class="spinner"></span>Preparing evidence and reasoning…</div>';
  const dialog=$("#detail");if(!dialog.open)dialog.showModal();dialog.scrollTop=0;
  try {
    const c=state.contexts.get(key)||await api("/api/context/"+encodeURIComponent(id)+"?analysis_id="+encodeURIComponent(analysisId));
    if(request!==caseRequest||state.data.analysis_id!==analysisId)return;
    state.contexts.set(key,c);state.detailContext=c;renderCase();
  }catch(error){if(request===caseRequest)$("#detail-body").innerHTML='<h2 id="detail-title">Investigation unavailable</h2><div class="notice error">'+esc(error.message)+'</div>';}
}

function briefOutput() {
  const result=state.brief;
  if(!result||result.analysis_id!==state.data.analysis_id)return '<div class="brief-placeholder">'+icon("spark")+'<h3>Every explanation needs evidence.</h3><p>Generate a briefing to see an individual Reasoning tab for every selected finding. Offline mode works immediately.</p></div>';
  return '<div class="notice">'+esc(result.confidence_note)+'</div><p class="brief-summary">'+esc(result.summary)+'</p>'+
    (result.explanations||[]).map(ex=>{
      const x=reviewExplanation(ex.alert_id), selected=state.briefTabs[ex.alert_id]||"reasoning", prefix="brief-"+ex.alert_id;
      return '<article class="brief-finding"><div class="brief-finding-head"><button class="text-btn" data-open="'+esc(ex.alert_id)+'">'+esc(ex.alert_id)+' ↗</button><span class="tag">'+(result.is_ai?"AI DRAFT":"OFFLINE TEMPLATE")+'</span></div>'+
        '<div class="case-tabs small-tabs" role="tablist" aria-label="'+esc("Explanation for "+ex.alert_id)+'">'+["summary","reasoning"].map(tab=>
        '<button role="tab" id="'+prefix+'-'+tab+'" aria-controls="'+prefix+'-panel" aria-selected="'+(selected===tab)+'" tabindex="'+(selected===tab?0:-1)+'" data-brief-id="'+esc(ex.alert_id)+'" data-brief-tab="'+tab+'">'+(tab==="reasoning"?"Reasoning":"Summary")+'</button>').join('')+'</div>'+
        '<div role="tabpanel" id="'+prefix+'-panel" aria-labelledby="'+prefix+'-'+selected+'">'+(selected==="reasoning"?explanationHtml(x):'<p>'+esc(ex.assessment)+'</p>')+'</div></article>';
    }).join('');
}
function saveFile(name, text, type) {
  const url=URL.createObjectURL(new Blob([text],{type})), a=document.createElement("a");
  a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),2000);
}
function exportCase() {
  const c=state.detailContext;if(!c)return;
  const content={application:"SILC",version:"3.0.0",exported_at:new Date().toISOString(),dataset_fingerprint:state.data.fingerprint,
    dataset:state.data.name,synthetic:state.data.synthetic,context:c,analyst_assessment:review(c.alert.alert_id),
    ai_explanation:reviewExplanation(c.alert.alert_id),review_activity:state.audit.filter(a=>a.key===noteKey(c.alert.alert_id)),
    caveat:"Observed facts, hypotheses and human decisions are separate. No containment actions are executed by this application."};
  saveFile(c.case_id+".json",JSON.stringify(content,null,2),"application/json");
  toast("Case exported with reasoning, evidence, and your saved assessment.");
}
function explanationReport() {
  let output="\n\n## Per-finding explanation summaries\n";
  for(const a of knownAlerts()) {
    const x=reviewExplanation(a.alert_id);if(!x)continue;
    output+="\n### "+a.case_id+" · "+a.alert_id+"\n"+
      (x.is_ai?"AI-generated advisory explanation":"Offline template; not AI")+"\nProvider: "+x.provider+" / "+x.model+"\n"+
      "Assessment: "+x.assessment+"\n\nReasoning: "+x.rationale+"\n\nEvidence references: "+x.evidence_ids.join(", ")+"\n"+
      "Alternatives: "+x.alternatives.join("; ")+"\nMissing evidence: "+x.missing_evidence.join("; ")+"\n"+
      "Suggested checks:\n"+x.next_steps.map(s=>"- "+s.action+": "+s.why).join("\n")+"\n"+
      "Hypothesis, not observed: "+x.hypothesis+"\nAI prediction confidence: "+x.prediction_confidence+"\n"+x.confidence_note+"\n";
  }
  output+="\n## Local analyst activity\n";
  for(const entry of state.audit.filter(e=>e.key.startsWith(state.data.fingerprint+":")))output+="- "+entry.time+" · "+entry.key.split(":")[1]+" · "+entry.action+"\n";
  output+="\nActivity uses the browser clock and is not tamper-proof. Check marks describe recorded analyst review, not executed defensive actions.\n";
  return output;
}
function captureDraft() {
  if(state.detailTab!=="assessment"||!$("#analyst-note"))return;
  state.drafts[noteKey(state.detailId)]={status:$("#review-status").value,note:$("#analyst-note").value,
    checks:[...document.querySelectorAll("[data-check-step]:checked")].map(e=>e.dataset.checkStep)};
}
function switchCaseTab(tab, focus=false) {
  if(!CASE_TABS[tab])return;
  captureDraft();state.detailTab=tab;renderCase();
  if(focus)$("#tab-"+tab)?.focus();
}
async function showReference(id, alertId) {
  if(!alertId)return;
  if(!$("#detail").open||state.detailId!==alertId)await openCase(alertId);
  if(state.detailId!==alertId||!state.detailContext)return;
  switchCaseTab("evidence");
  const row=[...$("#detail-body").querySelectorAll("[data-event-id]")].find(el=>el.dataset.eventId===id);
  if(row){row.classList.add("evidence-selected");row.scrollIntoView({block:"center"});}
}
function workspaceClick(e) {
  const mode=e.target.closest("[data-mode]");
  if(mode){state.mode=mode.dataset.mode;render();return true;}
  const filter=e.target.closest("[data-filter-kind]");
  if(filter){if(filter.dataset.filterKind==="protocol")goToLogs("",filter.dataset.filterValue);else filterBy(filter.dataset.filterKind,filter.dataset.filterValue);return true;}
  const bucket=e.target.closest("[data-bucket]");
  if(bucket){filterBy("bucket",bucket.dataset.bucket);return true;}
  const tab=e.target.closest("[data-case-tab]");
  if(tab){switchCaseTab(tab.dataset.caseTab,true);return true;}
  const briefTab=e.target.closest("[data-brief-tab]");
  if(briefTab){state.briefTabs[briefTab.dataset.briefId]=briefTab.dataset.briefTab;render();$("#brief-"+briefTab.dataset.briefId+"-"+briefTab.dataset.briefTab)?.focus();return true;}
  const node=e.target.closest("[data-graph-ip]");
  if(node){goToLogs(node.dataset.graphIp);return true;}
  const reference=e.target.closest("[data-evidence-id]");
  if(reference){showReference(reference.dataset.evidenceId,reference.closest("[data-explanation-alert]")?.dataset.explanationAlert);return true;}
  const action=e.target.closest("[data-action]")?.dataset.action;
  if(action==="clear-bucket"){state.bucket=null;state.page=1;render();return true;}
  if(action==="log-prev"||action==="log-next"){state.logOffset=Math.max(0,state.logOffset+(action==="log-next"?50:-50));loadLogs();return true;}
  if(action==="reset-logs"){goToLogs();return true;}
  if(action==="export-case"){e.preventDefault();exportCase();return true;}
  return false;
}
function workspaceInput(e) {
  if(e.target.id==="timeline-window"){state.timelineStart=Number(e.target.value);$("#timeline-plot").innerHTML=interactiveTimeline(true);return true;}
  if(e.target.id==="log-search"){state.logQuery=e.target.value;state.logOffset=0;clearTimeout(loadLogs.timer);loadLogs.timer=setTimeout(loadLogs,250);return true;}
  return false;
}
function workspaceChange(e) {
  const filterFields={"type-filter":"type","confidence-filter":"confidence","ai-confidence-filter":"aiConfidence"};
  if(filterFields[e.target.id]){state[filterFields[e.target.id]]=e.target.value;state.page=1;$("#queue-content").innerHTML=queueContent();return true;}
  if(["log-protocol","log-severity","log-linked"].includes(e.target.id)){
    state.logProtocol=$("#log-protocol").value;state.logSeverity=$("#log-severity").value;state.logLinked=$("#log-linked").checked;state.logOffset=0;loadLogs();return true;
  }
  return false;
}
function wireWorkspaceInteractions() {
  const tooltip=$("#chart-tooltip");
  let tipTarget=null;
  function hideTip() {tooltip.hidden=true;if(tipTarget)tipTarget.removeAttribute("aria-describedby");tipTarget=null;}
  function positionTip(x,y) {
    tooltip.style.left=Math.max(10,Math.min(x+14,window.innerWidth-290))+"px";
    tooltip.style.top=Math.max(10,Math.min(y+14,window.innerHeight-tooltip.offsetHeight-12))+"px";
  }
  function showTip(target,x,y) {
    const host=target.closest("dialog")||document.body;
    if(tooltip.parentElement!==host)host.appendChild(tooltip);
    if(tipTarget&&tipTarget!==target)tipTarget.removeAttribute("aria-describedby");
    tipTarget=target;target.setAttribute("aria-describedby","chart-tooltip");
    tooltip.textContent=target.dataset.tooltip;tooltip.hidden=false;positionTip(x,y);
  }
  document.addEventListener("pointerover",e=>{const target=e.target.closest("[data-tooltip]");if(target)showTip(target,e.clientX,e.clientY);});
  document.addEventListener("pointermove",e=>{if(!tooltip.hidden)positionTip(e.clientX,e.clientY);});
  document.addEventListener("pointerout",e=>{if(e.target.closest("[data-tooltip]"))hideTip();});
  document.addEventListener("focusin",e=>{const target=e.target.closest("[data-tooltip]");if(target){const r=target.getBoundingClientRect();showTip(target,r.left,r.bottom);}});
  document.addEventListener("focusout",hideTip);
  document.addEventListener("keydown",e=>{
    if(e.key==="Escape")hideTip();
    const tab=e.target.closest('[role="tab"]');
    if(tab&&["ArrowLeft","ArrowRight","Home","End"].includes(e.key)){
      e.preventDefault();
      const siblings=[...tab.parentElement.querySelectorAll('[role="tab"]')], index=siblings.indexOf(tab);
      const next=e.key==="Home"?0:e.key==="End"?siblings.length-1:(index+(e.key==="ArrowRight"?1:-1)+siblings.length)%siblings.length;
      siblings[next].click();
    }
    if(e.target.closest("[data-graph-ip]")&&["Enter"," "].includes(e.key)){e.preventDefault();e.target.closest("[data-graph-ip]").click();}
    if(e.target.matches('svg [role="button"][data-filter-kind]')&&["Enter"," "].includes(e.key)){e.preventDefault();filterBy(e.target.dataset.filterKind,e.target.dataset.filterValue);}
  });
}
