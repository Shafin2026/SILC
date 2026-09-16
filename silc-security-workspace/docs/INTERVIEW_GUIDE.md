# Explain SILC to a recruiter

SILC stands for **Security Intelligence & Log Correlation**.

The strongest demonstration is one complete investigation: show the signal, open the evidence, explain uncertainty, and record a decision.

## A short introduction

> SILC is my cybersecurity investigation project. It turns structured network logs into evidence-linked findings and an interactive analyst workspace. Every finding has a Reasoning tab explaining the trigger, missing evidence and possible false positives. An optional AI model adds an interpretation with citations, while the analyst makes the final decision.

Practice this in your own words. Be ready to show the code behind each feature you discuss.

## A three-minute demonstration

### 1. Overview — 30 seconds

Start with the included sample: **11,000 synthetic events, 10 findings, five rule types**.

Hover a timeline bar to show the time, record count and newly observed findings. Hover the severity chart, then click **Critical**.

Say:

> These charts use the analysis results. Clicking a severity or time interval narrows the investigation. The sample is reproducible, so another person can run the repository and compare the results.

### 2. Reasoning — 45 seconds

Open **Possible SYN flood**.

Point out:

- 85 exact SYN records for the same source, destination and port.
- A threshold of 60 in an aligned one-minute UTC bucket.
- A Critical review priority, with a fixed score of 95.
- “Pattern supported” describing the rule match.
- Missing completed-handshake and service-health measurements.
- The earlier-bucket comparison, which is not a verified normal baseline.

Say:

> This finding crossed a clear threshold. That supports investigating the pattern, but it does not prove the service was unavailable. I would check completed TCP handshakes, retransmissions, service metrics and any approved load test.

### 3. Evidence and Connections — 40 seconds

Open **Evidence** and show the 85 matching records and stable IDs.

Open **Connections**. Hover a node or connection to see its information. Explain that the graph counts observed CSV relationships in a nearby time window.

Point to the distinct **Observed** and **Hypothesis — not observed** stages.

Say:

> The graph gives context around a finding. A shared IP or nearby timestamp does not prove causation. The follow-on stage is a question to investigate, not an event the system claims happened.

### 4. AI briefing — 35 seconds

Choose **Explain with a model**. For a dependable first walkthrough, select **Offline briefing** and generate it.

Show the small **Reasoning** tab and click an event reference. It opens the matching evidence.

Say:

> Offline mode uses a deterministic template. With a configured local or cloud model, the same view shows a model interpretation. The backend requires an explanation for every selected finding and validates its event IDs. Those checks catch missing or invented references, but a person still has to assess whether the interpretation makes sense.

Use a live model in the demonstration only after testing it successfully.

### 5. Assessment and export — 30 seconds

Return to the case, open **Assessment**, mark it **Investigating**, and save a note such as:

> The SYN count exceeded the one-minute threshold. Service disruption remains unconfirmed. Next checks: handshake completion, service health and whether this source was part of an approved load test.

Export the case or Markdown report.

Say:

> The final decision is a recorded analyst assessment. The model cannot block traffic or change case status. I keep a local activity history and can export the evidence and explanation with the review.

## Understand the architecture

| Layer | Your explanation |
| --- | --- |
| Validation | Check schema, unique IDs, timestamps, addresses, ports and file bounds before analysis |
| Detection | Group records by rule context and fixed UTC buckets; retain the complete matching IDs |
| Context | Attach rule explanations, missing telemetry, earlier-bucket comparisons and nearby connections |
| API | Serve both the interface and data from one local FastAPI process |
| Frontend | Keep navigation, filters, tabs and chart interactions synchronized with the analysis |
| Model adapter | Send selected context, validate structured explanations and keep keys on the backend |
| Assessment | Save the analyst's status, note and completed checks, scoped to the dataset |
| Export | Combine findings, reasoning, model drafts and human review into a reviewable artifact |

## Questions to practice

**Why rules and an LLM together?**

Rules make the trigger reproducible and inspectable. The model helps summarize context and suggest checks. Keeping their outputs separate helps an analyst question the interpretation.

**What does 95 mean?**

It is the configured Critical priority, not 95% accuracy or confidence. The model did not calculate it.

**How is “Reasoning” implemented?**

The rule explanation comes from the rule metadata and matching records. Model explanations follow a strict schema requiring rationale, evidence IDs, alternatives, missing evidence, suggested checks and a confidence label. The tab presents a concise justification grounded in those inputs.

**How do you handle false positives?**

Show a benign explanation for the specific rule: an approved scanner, mistyped password, authorized load test or lab indicator. Request missing context and record why the finding is benign, needs escalation or remains uncertain.

**How is the comparison calculated?**

It uses earlier complete buckets for the same relevant context within the uploaded data. Empty buckets mean zero recorded matches. Logging completeness is unknown, so this is not a claim about normal traffic.

**How do you stop fabricated model evidence?**

Require every selected alert exactly once and require citations from the event IDs supplied for that alert. Reject invalid IDs and incomplete structures. This does not prove semantic accuracy; a valid citation can still be misinterpreted.

**How is prompt injection handled?**

Log text is treated as untrusted data. The model receives no execution tools, output must match a strict schema, and the browser escapes model text. These controls limit what an injected response can do; they are not proof that the model will always ignore misleading text.

**Where are notes stored?**

In browser local storage under a full dataset fingerprint and alert ID. They survive reload in the same browser and local address. AI output and unsaved drafts are session-only. This is a single-user lab, so a production version would need authenticated server storage and a trustworthy audit trail.

**How did you verify it?**

The delivery has 52 passing Python tests, 38 passing frontend logic checks, syntax checks and a local HTTP startup check. The frontend tests use a small DOM stub. Describe your own browser and live-model checks after completing them.

**What are the main limitations?**

Fixed windows can miss activity split across boundaries. The indicators and traffic are synthetic. There is no measured real-world precision/recall, live capture, trained detector, authenticated deployment or automatic response.

**What would you improve next?**

Choose one improvement and explain its value: sliding windows for boundary cases, realistic labeled evaluation data, richer endpoint telemetry, a server-backed case database, or more frontend exploration controls.

## A concrete experiment to understand

The sample SYN burst has 85 records. In `src/config.py`, the threshold is 60.

1. Predict what happens if the threshold becomes 90.
2. Change `SYN_FLOOD_PACKETS` to 90.
3. Stop and restart SILC so the cached sample is recalculated.
4. Inspect the sample again.
5. Record the result in your project journal.
6. Restore 60 and rerun the tests.

Expected result: the SYN rule no longer flags that burst, leaving nine alerts. The sample-expectation tests are deliberately tied to the default configuration, so restore it before using those tests as the baseline.

This experiment demonstrates that you understand the trigger, cache lifecycle and reproducible validation.

## Resume wording

**SILC — Security Intelligence & Log Correlation | Cybersecurity Portfolio Project**

- Built a Python/FastAPI log-analysis workspace with five reproducible detection rules and evidence-linked review of 11,000 synthetic events.
- Created an interactive investigation interface with searchable logs, chart filters, per-finding Reasoning, analyst assessments and report exports.
- Integrated optional local/cloud model explanations with structured response validation and event-reference checks.

Use the model-integration bullet after you have successfully exercised the provider you discuss. Describe additional metrics or personal changes only when you can reproduce and explain them.

This is a new synthetic portfolio lab. If asked about the college project, distinguish that earlier group work from the current repository.

## GitHub presentation

Use repository name `silc-security-workspace`.

Description:

> An interactive cybersecurity investigation lab with Python detections, evidence reasoning, optional LLM explanations and analyst case review.

Include:

- The source files, README, tests, documentation and synthetic CSV.
- Your own screenshot of Overview.
- A screenshot showing Reasoning and evidence.
- A short screen recording of the investigation above.
- One exported synthetic case with your assessment.
- A commit for a change you can explain.

Keep private keys, local environments and confidential records out of the repository.
