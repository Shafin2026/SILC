/* No browser or npm dependencies. Checks rendering/filter logic in a minimal DOM stub.
   This is NOT visual, layout, accessibility, or real-browser testing. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const root = path.resolve(__dirname, '..');
const py = process.platform === 'win32' ? path.join(root,'.venv','Scripts','python.exe') : path.join(root,'.venv','bin','python');
const data = JSON.parse(execFileSync(py, ['-c',
  'import json, asyncio; from src.api import sample, public_analysis; from src.rules import RULES; from src.ai_providers import configured_providers, summarize_alerts; from src.intelligence import context, ai_context; item=sample(); alerts=item["alerts"].head(2).to_dict(orient="records"); print(json.dumps({"analysis":public_analysis(item),"rules":RULES,"providers":configured_providers(),"cases":[context(item,a) for a in alerts],"brief":asyncio.run(summarize_alerts([ai_context(item,a) for a in alerts],"offline"))}))'
], {cwd:root,encoding:'utf8'}));
const elements = new Map();
function el(id) {
  if (!elements.has(id)) elements.set(id, {innerHTML:'',textContent:'',hidden:false,value:'',disabled:false,
    open:false,setAttribute(){},removeAttribute(){},addEventListener(){},focus(){},showModal(){this.open=true;},close(){this.open=false;},
    querySelectorAll:()=>[],classList:{toggle(){},add(){},remove(){}}});
  return elements.get(id);
}
const storage = new Map();
const context = vm.createContext({
  console, Date, Set, Map, Number, String, Math, JSON, Error, encodeURIComponent,
  setTimeout:()=>1,clearTimeout(){},URLSearchParams,
  localStorage:{getItem:key=>storage.get(key)||null,setItem:(key,value)=>storage.set(key,value)},
  document:{querySelector:el,querySelectorAll:()=>[],addEventListener(){}},
  window:{addEventListener(){},scrollTo(){}},location:{hash:'#overview'},
  fixture:data,
  fetch:async url=>({ok:true,json:async()=>url==='/api/analysis'?data.analysis:url==='/api/rules'?data.rules:String(url).startsWith('/api/context/')?data.cases[0]:data.providers})
});
vm.runInContext(fs.readFileSync(path.join(root,'frontend','workspace.js'),'utf8'),context);
vm.runInContext(fs.readFileSync(path.join(root,'frontend','app.js'),'utf8'),context);
let count=0;
function check(name, expression) {
  assert.equal(vm.runInContext(expression,context),true,name);
  count++;
  console.log('PASS '+name);
}
setImmediate(async()=>{
  check('sample renders', "overview().includes('11,000') && overview().includes('Possible SYN flood')");
  check('all seven views render', "[overview,queue,logsView,uploadView,rulesView,briefingView,guideView].every(f=>f().includes('<h1>'))");
  check('critical filter', "state.severity='Critical'; filteredAlerts().length === 1");
  check('IP search', "state.severity='all'; state.query='203.0.113.45'; filteredAlerts().length === 1");
  check('search empty state', "state.query='no-match-anywhere'; queueContent().includes('No matching alerts')");
  check('reset view state', "state.query=''; state.status='all'; filteredAlerts().length === 10");
  check('assessment updates filter', "state.notes[noteKey(state.data.alerts[0].alert_id)]={status:'Investigating',note:'Check handshakes'}; state.status='Investigating'; filteredAlerts().length === 1");
  check('HTML escaping', "esc('<img src=x onerror=alert(1)>').includes('&lt;img') && !esc('<img>').includes('<img>')");
  check('uploaded names escaped', "state.data.name='<script>bad</script>'; !datasetBar().includes('<script>')");
  check('AI output escaped', "state.brief={analysis_id:state.data.analysis_id,is_ai:true,provider:'mock',model:'mock',summary:'<script>bad</script>',disclaimer:'Review'}; briefingView().includes('&lt;script&gt;')");
  check('offline explicitly not AI', "state.brief=null; briefingView().includes('not an AI response')");
  check('fixed-window limitation visible', "rulesView().includes('not sliding windows')");
  check('case ID search', "state.status='all';state.query=state.data.alerts[0].case_id;filteredAlerts().length===1");
  check('detection type filter', "state.query='';state.type='Port scan';filteredAlerts().length===1");
  check('confidence and type compose', "state.confidence='Indicator only';filteredAlerts().length===0");
  check('indicator support filter', "state.type='all';filteredAlerts().length===7");
  check('timeline filtering', "state.confidence='all';state.bucket='2026-09-01T10:00:00+00:00';filteredAlerts().length===1");
  check('reset timeline', "state.bucket=null;filteredAlerts().length===10");
  check('hover metadata uses real numbers', "interactiveTimeline().includes('85') && interactiveTimeline().includes('data-tooltip=')");
  check('timeline drag preserves the slider', "$('#timeline-content').innerHTML=interactiveTimeline();const beforeSlider=$('#timeline-content').innerHTML;workspaceInput({target:{id:'timeline-window',value:'1'}});$('#timeline-content').innerHTML===beforeSlider && $('#timeline-plot').innerHTML.includes('timeline-bar') && state.timelineStart===1");
  check('donut segments have hover and keyboard metadata', "severityChart().includes('class=\"donut-segment\" role=\"button\" tabindex=\"0\"') && severityChart().includes('Critical\\n1 alerts')");
  check('executive view changes information density', "state.mode='executive';overview().includes('EXECUTIVE BRIEF') && !overview().includes('Detection patterns')");
  check('analyst charts return', "state.mode='analyst';overview().includes('Detection patterns')");
  await vm.runInContext("openCase(state.data.alerts[0].alert_id)",context);
  check('case opens on reasoning', "state.detailTab==='reasoning' && $('#detail-body').innerHTML.includes('WHY THIS FINDING EXISTS')");
  check('reasoning distinguishes confidence', "ruleReasoning(state.detailContext).includes('AI prediction confidence') && ruleReasoning(state.detailContext).includes('not the probability')");
  check('observed and hypothetical stages distinct', "connectionsHtml(state.detailContext).includes('HYPOTHESIS · NOT OBSERVED') && connectionsHtml(state.detailContext).includes('OBSERVED')");
  check('interactive graph nodes have keyboard access', "graphHtml(state.detailContext).includes('role=\"button\" tabindex=\"0\"') && graphHtml(state.detailContext).includes('data-tooltip=')");
  check('offline briefing binds each explanation', "state.brief={...fixture.brief,analysis_id:state.data.analysis_id};ingestBrief(state.brief);Object.keys(state.explanations).length===2");
  check('each briefing has a reasoning tab', "(briefOutput().match(/>Reasoning<\\/button>/g)||[]).length===2");
  check('AI output cannot change review decisions', "const before=JSON.stringify(state.notes);ingestBrief({...state.brief,is_ai:true});JSON.stringify(state.notes)===before && state.data.alerts[0].severity==='Critical'");
  check('prediction confidence filter', "reviewExplanation(state.data.alerts[0].alert_id).prediction_confidence='Moderate';state.aiConfidence='Moderate';filteredAlerts().length===1");
  check('save analyst assessment', "state.aiConfidence='all';$('#review-status').value='Benign';$('#analyst-note').value='Approved load test verified by analyst.';recordAssessment();review(state.detailId).status==='Benign' && state.audit.length===1");
  check('review survives storage round trip', "state.notes=Object.create(null);workspaceStarted=false;initWorkspace();review(state.detailId).note==='Approved load test verified by analyst.'");
  check('saved notes are escaped on render', "state.notes[noteKey(state.detailId)].note='<script>unsafe</script>';assessmentHtml(state.detailContext).includes('&lt;script&gt;') && !assessmentHtml(state.detailContext).includes('<script>')");
  check('model rationale is escaped', "reviewExplanation(state.detailId).rationale='<img src=x onerror=bad()>';explanationHtml(reviewExplanation(state.detailId)).includes('&lt;img') && !explanationHtml(reviewExplanation(state.detailId)).includes('<img')");
  check('case evidence links are actionable', "explanationHtml(reviewExplanation(state.detailId)).includes('data-evidence-id=')");
  check('report includes reasoning and activity', "explanationReport().includes('Reasoning:') && explanationReport().includes('Local analyst activity')");
  check('selected related case stays visible in briefing picker', "state.contexts.set('external',{alert:{...state.data.alerts[0],alert_id:'ALT-FFFFFFFFFF'}});state.selected=new Set(['ALT-FFFFFFFFFF']);briefingView().includes('data-select-alert=\"ALT-FFFFFFFFFF\" checked')");
  console.log(count+' frontend logic checks passed. Real browser QA is still required.');
});
