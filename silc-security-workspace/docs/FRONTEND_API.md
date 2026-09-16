# Frontend API contract

FastAPI serves both the frontend and API at the local address printed by the launcher. All frontend requests use relative paths. There is no second frontend server or CORS configuration.

The schema is available at `/openapi.json`. Swagger at `/docs` uses external assets.

## Routes

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Status, local-lab mode and version |
| GET | `/api/analysis?analysis_id=sample` | Metrics, fingerprint, timeline and first 500 findings |
| GET | `/api/summary?analysis_id=sample` | Same analysis without the alert array |
| GET | `/api/alerts?analysis_id=sample&severity=High&limit=100` | Public findings; limit 1–500 |
| GET | `/api/context/{alert_id}?analysis_id=sample` | Reasoning, evidence, comparison, connections and next checks |
| GET | `/api/evidence/{alert_id}?analysis_id=sample` | Up to 100 matching raw records |
| GET | `/api/events?analysis_id=sample&limit=50&offset=0` | Search and paginate the entire normalized dataset |
| GET | `/api/rules` | Rule descriptions, triggers and limitations |
| GET | `/api/providers` | Configuration state; never keys |
| GET | `/api/sample.csv` | Synthetic sample download |
| GET | `/api/report?analysis_id=sample` | Markdown report and reasoning for the top 100 findings |
| POST | `/api/analyze-file` | Multipart field `file`; create an in-memory analysis |
| POST | `/api/ai-summary` | Offline/local/cloud explanations of selected findings |

## Identity and lifecycle

- `analysis_id` identifies an uploaded analysis in the current server process. Send it with all dataset-specific requests.
- `fingerprint` is a SHA-256 digest of normalized data sorted by event ID. Identical normalized data retains the same identity across filename changes and re-uploads.
- `alert_id` is the stable detection identifier. Do not use a row index.
- `case_id` is the displayed incident label derived from the fingerprint and alert ID. It is not a globally registered incident number.
- Browser assessment keys use the full fingerprint plus alert ID.
- Public responses remove internal underscore-prefixed fields. The complete private evidence index supports full-dataset log linking beyond the 100-row preview.

Uploads expire after an hour, a process restart, or eviction when more than three are retained. Expired IDs return 404. The built-in `sample` remains available.

Fingerprints cover dataset content, not rule-code versions. Export the project version and your experiment notes when changing rules.

## Analysis fields

Counts include every finding and event. `alerts_truncated` indicates that the returned alert list stops at 500.

`timeline` contains aligned 10-minute UTC buckets with `time`, `events` and `alerts`. The alert count means findings **first observed** in the bucket, not all active alerts.

`linked_events` counts unique records linked to any finding, using complete evidence IDs. `evidence_events_previewed` counts the union of public evidence previews and can be lower on larger datasets.

## Log explorer

Optional parameters:

| Parameter | Behavior |
| --- | --- |
| `q` | Literal case-insensitive substring across event ID, IPs, username and domains; max 128 characters |
| `protocol` | Exact normalized protocol |
| `linked_only` | Only events linked to a finding |
| `severity` | Events linked to at least one finding of that severity |
| `start` | Inclusive timezone-aware timestamp |
| `end` | Exclusive timezone-aware timestamp |
| `offset` | 0–20,000 |
| `limit` | 1–100, default 50 |

Response: `total`, `offset`, `limit`, `events`. Each event includes its `alert_ids`. Records are sorted by timestamp and event ID. The current UI exposes search, protocol, linked-only and severity; time bounds are available through the API.

## Case context

`/api/context/{alert_id}` returns:

- `alert`, `case_id`, and `rule`.
- `reasoning`: observations, trigger, confidence meaning, evidence quality, missing telemetry, alternatives, limitations, comparison and ATT&CK reference.
- `evidence`: the exact public preview, sorted by timestamp, with linked alert IDs.
- `related_events` and `related_alerts`, plus their full totals.
- `graph`: the primary connection and up to five others observed in the correlation window.
- `attack_path`: an observed rule match and an explicitly hypothetical playbook stage.
- `next_steps`: `verify`, `collect`, `decide`, each with its reason.
- `business_impact`: possible impact, with uncertainty.

Correlation uses a shared endpoint within 15 minutes of the finding. It does not establish causation. Earlier-bucket comparisons include zero recorded matches and disclose that collection completeness and normal behavior are unknown.

## Briefing request

```json
{
  "analysis_id": "sample",
  "alert_ids": [],
  "provider": "offline",
  "consent_to_cloud": false
}
```

An empty ID list selects the top five. An explicit list is limited to ten. Provider IDs: `offline`, `ollama`, `gemini`, `deepseek`, `openai`, `anthropic`.

Cloud calls require server opt-in, key/model configuration and `consent_to_cloud=true`. One request runs at a time; another receives 429.

## Briefing response

Top-level fields include `analysis_id`, `alert_ids`, `provider`, `model`, `summary`, `is_ai`, `confidence_note`, `disclaimer` and `explanations`.

Each explanation has:

```json
{
  "alert_id": "the-selected-alert-id",
  "assessment": "A concise evidence-based assessment.",
  "rationale": "Why the observations support this interpretation and what they cannot prove.",
  "evidence_ids": ["a-supplied-event-id"],
  "alternatives": ["A possible benign explanation."],
  "missing_evidence": ["Telemetry needed to resolve uncertainty."],
  "next_steps": [{"action": "An analyst check.", "why": "The purpose of that check."}],
  "hypothesis": "An explicitly unconfirmed possible future stage.",
  "prediction_confidence": "Not assessed"
}
```

Confidence values are Low, Moderate, High or Not assessed. They are not percentages. Strings, list sizes, alert coverage and citations are validated; arbitrary extra keys are rejected. Model output must always be rendered as untrusted text.

The offline template uses the same explanation structure with `is_ai=false` and no prediction.

## CSV schema

| Required column | Constraint |
| --- | --- |
| event_id | Unique, nonempty ID |
| timestamp | ISO timestamp with Z or numeric timezone offset; at most 7-day span |
| source_ip | IPv4 or IPv6 |
| destination_ip | IPv4 or IPv6 |
| destination_port | Integer 0–65535 |
| protocol | TCP, UDP, DNS, HTTP or ICMP |
| tcp_flags | Text or blank; the SYN rule requires exact SYN |
| username | Account identifier or blank |
| auth_result | success, failure or blank |
| dns_query | Domain name or blank |
| http_status | HTTP 100–599, blank or 0 |
| redirect_domain | Domain name, not a full URL, or blank |

Additional columns are retained in previews, up to 32 total. The sample also has source_port, action and bytes_sent.

## Errors and browser boundaries

400 malformed input or invalid selection; 404 missing/expired data; 413 oversized upload; 422 schema error; 429 busy model request; 502 provider failure; 503 sample missing.

Render errors as text and preserve valid prior results. Host validation, same-origin POST checks, bounded bodies and a content security policy support the local boundary. They do not provide authentication for public hosting.
