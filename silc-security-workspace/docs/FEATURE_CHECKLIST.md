# SILC feature checklist

This maps the requested project workflow to the delivered implementation.

| Requirement | Implementation | Practical boundary |
| --- | --- | --- |
| One complete download | Source, data, launcher, tests and guides in one ZIP | Python dependencies install on first run |
| Colorful, professional frontend | Navy navigation, light content, coordinated accent colors and severity labels | Real-browser visual check remains on the Mac checklist |
| Easy navigation | Seven areas, persistent sidebar, search/filter controls and case tabs | Queue displays the first 500 findings |
| Interactive charts | Hover/focus details, clickable severity/type/protocol charts and timeline slider | Values come from the loaded CSV |
| Reasoning for every finding | Default case tab with trigger, observations, alternatives and limits | Rule match is not proof of compromise |
| Reasoning for model output | Per-finding Reasoning tab; rationale and citation validation | Structural validation does not prove semantic correctness |
| Local or cloud AI | Offline, Ollama, Gemini, DeepSeek, OpenAI and Claude adapters | Live provider setup/test requires the user's local model or account |
| Evidence quality and missing logs | Partial-telemetry label and rule-specific missing evidence | No fabricated endpoint or service-health telemetry |
| Distinct confidence labels | Rule-support category and AI prediction self-assessment | No calibrated confidence percentage |
| Earlier comparison | Same-context bucket median plus threshold | This CSV's prior data is not a verified normal baseline |
| Event correlation | Nearby records, related findings and observed connection graph | Shared endpoints/time do not establish causation |
| Attack-stage context | Separate observed and hypothetical stage cards | Playbook hypotheses are not observed attacks |
| ATT&CK mapping | Official technique links with behavioral/hypothesis labels | No actor attribution or confirmed kill chain |
| Guided investigation | Verify, collect and decide checklist with explanations | Checks record analyst review; no automatic security action |
| Analyst assessments | Status, notes, saved checks and local history | Same browser/local address; no multi-user database |
| Case identity | Dataset fingerprint plus stable detection ID | Rule-version changes need a separate experiment record |
| Searchable logs | Full CSV search, protocol/severity/link filters and pagination | Input limits documented in the API guide |
| Analyst/executive modes | Detailed charts or concise impact/review overview | Business impact is qualified, not asserted |
| Exportable results | Markdown report and individual JSON case | Bounded evidence previews; export session AI before reload |
| Recruiter explanation | Three-minute demo, code map, interview answers and journal | Practice with results you have personally verified |
| Repository presentation | SILC branding and GitHub handoff guide | No GitHub repository is published by the download |

## Validation

The current delivery passes 52 Python tests and 38 frontend logic checks. See VALIDATION.md for scope, the local startup check and remaining manual checks.
