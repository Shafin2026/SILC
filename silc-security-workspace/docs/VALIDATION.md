# Validation status · SILC 3.0

Delivery checks completed on September 15, 2026 in the Linux build environment with Python 3.12.

## Passed

- **52 Python tests:** sample totals, all five rules, threshold boundaries, fixed-window behavior, CSV validation, upload isolation, host/origin checks, evidence linking, case fingerprints, comparison calculations, log filters, report context, offline explanations and all five mocked provider adapters.
- **38 frontend logic checks:** all seven views, composed filters, real chart metadata, slider update behavior, donut controls, case tabs, distinct confidence labels, observed/hypothetical stages, per-finding Reasoning, evidence links, saved-review round trips and escaped untrusted text.
- JavaScript syntax checks for both frontend scripts.
- Bash syntax checks for both launcher scripts.
- **Six live local HTTP startup checks:** launcher execution from another folder; occupied-port fallback; sample totals; reasoning/evidence/log routes; assets and report delivery; offline explanation/citations; and clean Control+C shutdown. The checks group related assertions into six reported results.

The full Python suite passed with one dependency deprecation warning from Starlette's test client. It did not affect the results.

## Startup behavior checked

The shell launcher was run from outside the project folder while another socket occupied port 8000. It selected port 8001, served the application, returned the expected 11,000 events / 10 alerts / 124 linked records, and stopped cleanly on a Control+C signal.

Requests to the running server exercised the page, JavaScript, CSS, favicon, full dataset analysis, case context, log explorer, report and offline briefing.

This checks the HTTP application and launcher. It is not a browser render or a physical Mac installation test.

## What remains to verify locally

- Rendered layout, touch interaction, tooltip placement, real browser focus behavior, responsive behavior and browser-triggered downloads.
- Screen-reader behavior and accessibility compliance.
- Automatic opening of your Mac's default browser and a fresh Python dependency installation on that Mac.
- Live inference with the selected Ollama or cloud model.
- GitHub publication or any public deployment.
- Real-world detection precision, recall, throughput or security effectiveness.

The browser available during the build could not access the local app. The frontend logic tests use a minimal DOM stub, not a real browser. No screenshot or rendered visual verification is claimed.

## Run automated checks

After startup has created the environment, open a second Terminal in the project folder:

```bash
.venv/bin/python -m pytest -q
```

If Node is installed, the optional frontend checks are:

```bash
node tests/frontend_logic.cjs
node --check frontend/app.js
node --check frontend/workspace.js
```

Shell syntax:

```bash
bash -n start.sh start.command
```

Node is not required to run the application.

## Browser checklist

Record the results in MY_CONTRIBUTIONS.md.

### Overview and navigation

- [ ] The local address printed in Terminal opens and shows 11,000 events, 10 findings and five rules.
- [ ] All seven navigation destinations load; browser Back returns to the previous section.
- [ ] Analyst/executive controls change the displayed detail.
- [ ] Hover a timeline bar; time, event count and finding count appear.
- [ ] Focus the same bar with the keyboard and read its details.
- [ ] Drag the timeline slider; it keeps responding throughout the drag.
- [ ] Click a timeline bucket; the queue shows findings first observed in that interval.
- [ ] Hover/click a severity segment and its labeled legend button.
- [ ] Click a detection bar and a protocol bar; the appropriate filtered view opens.

### Findings and evidence

- [ ] Critical filters to one SYN finding.
- [ ] Searching 203.0.113.45 returns the brute-force finding.
- [ ] Search a nonexistent value; a useful empty state appears.
- [ ] Severity, type, review and confidence filters combine correctly.
- [ ] Open the SYN case; Reasoning is the default tab.
- [ ] Its explanation shows 85 matching records and a threshold of 60.
- [ ] The case distinguishes rule support, partial evidence and AI prediction confidence.
- [ ] Evidence shows the matching records and can scroll without page-wide overflow.
- [ ] Connections shows observed records separately from hypotheses.
- [ ] Graph node activation opens that IP's log search.
- [ ] Nearby events and related findings can be explored.

### Assessments and export

- [ ] Write an assessment, switch tabs and return; the unsaved draft is preserved during the session.
- [ ] Save Investigating; the queue and status filter reflect it.
- [ ] Refresh on the same local address; the sample assessment is still available.
- [ ] Export a case JSON file; verify reasoning, context and saved review.
- [ ] Export Markdown; verify findings and saved assessments.
- [ ] Understand that clearing browser storage or changing the local port affects stored reviews.

### AI briefing

- [ ] Open one case, choose Explain with a model and generate Offline briefing.
- [ ] A Reasoning tab appears for that finding and the output is labeled as an offline template.
- [ ] Click an evidence reference; the corresponding record opens and highlights.
- [ ] With Ollama stopped, a failed request leaves the rule results available.
- [ ] After setting up a live model, request one explanation and review its accuracy and citations.
- [ ] AI explanations do not change saved analyst statuses.
- [ ] Export before reloading; session model output does not persist across refresh.
- [ ] Cloud selection requires configuration and the per-request confirmation.

### Imports and accessibility

- [ ] Download the sample CSV, upload it and compare totals.
- [ ] Try a malformed CSV and read the useful error.
- [ ] Try a valid dataset without seeded patterns; the app handles zero findings.
- [ ] Search and paginate Log explorer, including linked-only and protocol filters.
- [ ] At about 390px width, navigation, filters and case tabs remain usable.
- [ ] At 200% zoom, labels and actions remain readable.
- [ ] Tab, Shift+Tab, Enter and Escape support investigation navigation.
- [ ] Case tabs support arrow keys, Home and End.
- [ ] A visible focus indicator remains on interactive controls.
- [ ] The browser console has no uncaught application errors.
