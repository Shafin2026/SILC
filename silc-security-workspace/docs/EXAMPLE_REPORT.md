# SILC · Incident Analysis Report

## Executive summary

The analysis pipeline processed **11,000 network events** and generated **10 alerts** for analyst review.

Source: synthetic lab telemetry.
An alert indicates evidence worth investigating, not confirmed malicious activity.

## Alert totals

- Critical: 1
- High: 8
- Medium: 1
- Low: 0

## Prioritized findings

Showing up to 100 prioritized findings out of 10 total alerts.

### 1. Possible SYN flood - Critical

- Source: `192.0.2.88`
- Alert ID: ALT-7080154C15
- Matching events: 85
- First/last seen (UTC): 2026-09-01T10:00:00+00:00 / 2026-09-01T10:00:54+00:00
- Destination: `172.16.0.50`
- Evidence: 85 SYN packets targeted port 443 within 1 minute
- Recommended action: Check handshake completion, service health, and baseline traffic. Preserve evidence; consider rate limiting only through an approved response process.

### 2. Possible brute force - High

- Source: `203.0.113.45`
- Alert ID: ALT-531B9F4AE8
- Matching events: 12
- First/last seen (UTC): 2026-09-01T08:20:00+00:00 / 2026-09-01T08:22:45+00:00
- Destination: `172.16.0.10`
- Evidence: 12 failed logins for admin within 5 minutes
- Recommended action: Check for later successful logins and verify the account owner. If unauthorized, escalate and consider approved account protection measures.

### 3. Suspicious DNS query - High

- Source: `10.0.7.77`
- Alert ID: ALT-688B45B758
- Matching events: 1
- First/last seen (UTC): 2026-09-01T11:00:00+00:00 / 2026-09-01T11:00:00+00:00
- Destination: `172.16.0.53`
- Evidence: Exact match to a lab-only indicator: credential-check.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 4. Suspicious DNS query - High

- Source: `10.0.7.77`
- Alert ID: ALT-F632102884
- Matching events: 1
- First/last seen (UTC): 2026-09-01T11:01:00+00:00 / 2026-09-01T11:01:00+00:00
- Destination: `172.16.0.53`
- Evidence: Exact match to a lab-only indicator: credential-check.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 5. Suspicious DNS query - High

- Source: `10.0.7.77`
- Alert ID: ALT-75BA2F4BC5
- Matching events: 1
- First/last seen (UTC): 2026-09-01T11:02:00+00:00 / 2026-09-01T11:02:00+00:00
- Destination: `172.16.0.53`
- Evidence: Exact match to a lab-only indicator: credential-check.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 6. Suspicious DNS query - High

- Source: `10.0.7.77`
- Alert ID: ALT-3B80D8558D
- Matching events: 1
- First/last seen (UTC): 2026-09-01T11:03:00+00:00 / 2026-09-01T11:03:00+00:00
- Destination: `172.16.0.53`
- Evidence: Exact match to a lab-only indicator: credential-check.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 7. Suspicious DNS query - High

- Source: `10.0.7.77`
- Alert ID: ALT-3C65488651
- Matching events: 1
- First/last seen (UTC): 2026-09-01T11:04:00+00:00 / 2026-09-01T11:04:00+00:00
- Destination: `172.16.0.53`
- Evidence: Exact match to a lab-only indicator: credential-check.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 8. Suspicious DNS query - High

- Source: `10.0.7.77`
- Alert ID: ALT-A61EA31F1E
- Matching events: 1
- First/last seen (UTC): 2026-09-01T11:05:00+00:00 / 2026-09-01T11:05:00+00:00
- Destination: `172.16.0.53`
- Evidence: Exact match to a lab-only indicator: credential-check.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 9. Suspicious HTTP redirect - High

- Source: `10.0.4.22`
- Alert ID: ALT-9FA7B30979
- Matching events: 1
- First/last seen (UTC): 2026-09-01T12:00:00+00:00 / 2026-09-01T12:00:00+00:00
- Destination: `172.16.0.30`
- Evidence: Exact match to a lab-only indicator: greatrecipesforme.example
- Recommended action: Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.

### 10. Port scan - Medium

- Source: `198.51.100.27`
- Alert ID: ALT-0C44E6E133
- Matching events: 20
- First/last seen (UTC): 2026-09-01T09:00:00+00:00 / 2026-09-01T09:03:10+00:00
- Destination: `172.16.0.25`
- Evidence: 20 unique destination ports contacted within 5 minutes
- Recommended action: Verify whether this is an approved vulnerability scanner. Correlate firewall logs and escalate unauthorized reconnaissance.

## Analyst decision

Validate each finding against asset ownership, approved activity, authentication history, and surrounding telemetry before escalation or containment.
## Reasoning and investigation context

Detection confidence describes rule support. It is not calibrated attack probability.


### INC-017FAF03-708015 · ALT-7080154C15

Observed: 85 SYN packets targeted port 443 within 1 minute

Why flagged: A connection-request burst may signal pressure on a service.

Rule: 60+ TCP SYN packets from one source to one destination port in an aligned 1-minute UTC bucket.

Detection confidence: Pattern supported. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 85 matching rows available.

Missing telemetry: Completed TCP handshakes and retransmissions; Service health and availability measurements; Historical traffic baseline and load-test schedule

Possible false positive: A legitimate connection surge, load test or retry storm.

Comparison: observed 85 SYN records; threshold 60; earlier median 0.0. Median of earlier same-context buckets in this dataset, including zero recorded matches. Logging completeness and normal behavior are unknown; this comparison does not trigger the alert.

ATT&CK reference: [T1498.001 · Direct Network Flood](https://attack.mitre.org/techniques/T1498/001/). Behavior reference; not attribution.

Hypothesis, not observed: Service disruption. Compare availability and completed handshakes before concluding that a denial of service occurred.

Next checks: Check completed handshakes, service health and traffic baseline. Request Completed TCP handshakes and retransmissions; Service health and availability measurements; Historical traffic baseline and load-test schedule. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-531B9F · ALT-531B9F4AE8

Observed: 12 failed logins for admin within 5 minutes

Why flagged: Repeated failures can indicate password guessing, but they can also be a misconfigured application.

Rule: 8+ failed logins for the same source, destination and username in an aligned 5-minute UTC bucket.

Detection confidence: Pattern supported. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 12 matching rows available.

Missing telemetry: Account ownership and authorized source inventory; Identity-provider session and MFA records; Endpoint process history

Possible false positive: A user with an old saved password or a service using expired credentials.

Comparison: observed 12 failed logins; threshold 8; earlier median 0.0. Median of earlier same-context buckets in this dataset, including zero recorded matches. Logging completeness and normal behavior are unknown; this comparison does not trigger the alert.

ATT&CK reference: [T1110.001 · Password Guessing](https://attack.mitre.org/techniques/T1110/001/). Behavior reference; not attribution.

Hypothesis, not observed: Unauthorized account access. Check for later successful authentication and confirm whether the account owner recognizes it.

Next checks: Look for a successful login after the failures. Confirm the account owner and source device. Request Account ownership and authorized source inventory; Identity-provider session and MFA records; Endpoint process history. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-688B45 · ALT-688B45B758

Observed: Exact match to a lab-only indicator: credential-check.example

Why flagged: An indicator match gives an analyst a concrete lead to investigate.

Rule: DNS queries are normalized to lowercase; an exact domain match triggers an alert.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence

Possible false positive: A security test, sandbox or stale indicator.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1071.004 · Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/). Hypothesis only; C2 is not established; not attribution.

Hypothesis, not observed: Follow-on connection to the resolved destination. Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2.

Next checks: Correlate endpoint and DNS history. These domains are fictional lab indicators. Request Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-F63210 · ALT-F632102884

Observed: Exact match to a lab-only indicator: credential-check.example

Why flagged: An indicator match gives an analyst a concrete lead to investigate.

Rule: DNS queries are normalized to lowercase; an exact domain match triggers an alert.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence

Possible false positive: A security test, sandbox or stale indicator.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1071.004 · Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/). Hypothesis only; C2 is not established; not attribution.

Hypothesis, not observed: Follow-on connection to the resolved destination. Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2.

Next checks: Correlate endpoint and DNS history. These domains are fictional lab indicators. Request Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-75BA2F · ALT-75BA2F4BC5

Observed: Exact match to a lab-only indicator: credential-check.example

Why flagged: An indicator match gives an analyst a concrete lead to investigate.

Rule: DNS queries are normalized to lowercase; an exact domain match triggers an alert.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence

Possible false positive: A security test, sandbox or stale indicator.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1071.004 · Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/). Hypothesis only; C2 is not established; not attribution.

Hypothesis, not observed: Follow-on connection to the resolved destination. Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2.

Next checks: Correlate endpoint and DNS history. These domains are fictional lab indicators. Request Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-3B80D8 · ALT-3B80D8558D

Observed: Exact match to a lab-only indicator: credential-check.example

Why flagged: An indicator match gives an analyst a concrete lead to investigate.

Rule: DNS queries are normalized to lowercase; an exact domain match triggers an alert.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence

Possible false positive: A security test, sandbox or stale indicator.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1071.004 · Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/). Hypothesis only; C2 is not established; not attribution.

Hypothesis, not observed: Follow-on connection to the resolved destination. Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2.

Next checks: Correlate endpoint and DNS history. These domains are fictional lab indicators. Request Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-3C6548 · ALT-3C65488651

Observed: Exact match to a lab-only indicator: credential-check.example

Why flagged: An indicator match gives an analyst a concrete lead to investigate.

Rule: DNS queries are normalized to lowercase; an exact domain match triggers an alert.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence

Possible false positive: A security test, sandbox or stale indicator.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1071.004 · Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/). Hypothesis only; C2 is not established; not attribution.

Hypothesis, not observed: Follow-on connection to the resolved destination. Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2.

Next checks: Correlate endpoint and DNS history. These domains are fictional lab indicators. Request Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-A61EA3 · ALT-A61EA31F1E

Observed: Exact match to a lab-only indicator: credential-check.example

Why flagged: An indicator match gives an analyst a concrete lead to investigate.

Rule: DNS queries are normalized to lowercase; an exact domain match triggers an alert.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence

Possible false positive: A security test, sandbox or stale indicator.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1071.004 · Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/). Hypothesis only; C2 is not established; not attribution.

Hypothesis, not observed: Follow-on connection to the resolved destination. Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2.

Next checks: Correlate endpoint and DNS history. These domains are fictional lab indicators. Request Validated indicator provenance and current reputation; DNS response and connection outcomes; Endpoint process and command-and-control evidence. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-9FA7B3 · ALT-9FA7B30979

Observed: Exact match to a lab-only indicator: greatrecipesforme.example

Why flagged: An unexpected redirect may move a browser to an untrusted destination.

Rule: HTTP status 300-399 and an exact redirect-domain indicator match.

Detection confidence: Indicator only. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 1 matching rows available.

Missing telemetry: Full browser/proxy redirect chain; Download, execution and endpoint telemetry; Validated indicator provenance

Possible false positive: A controlled simulation or research sandbox.

Comparison: observed 1 indicator matches; threshold None; earlier median None. This is an exact indicator match, not a baseline anomaly test.

ATT&CK reference: [T1189 · Drive-by Compromise](https://attack.mitre.org/techniques/T1189/). Hypothesis only; browser exploitation is not established; not attribution.

Hypothesis, not observed: Untrusted download or browser exploitation. Seek download and execution records; a redirect alone does not establish either outcome.

Next checks: Inspect proxy and browser evidence. A redirect does not prove a download or infection. Request Full browser/proxy redirect chain; Download, execution and endpoint telemetry; Validated indicator provenance. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.


### INC-017FAF03-0C44E6 · ALT-0C44E6E133

Observed: 20 unique destination ports contacted within 5 minutes

Why flagged: A source exploring many ports may be looking for exposed services.

Rule: 12+ distinct TCP destination ports from one source to one destination in an aligned 5-minute UTC bucket.

Detection confidence: Pattern supported. Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.

Evidence quality: Partial telemetry; 20 matching rows available.

Missing telemetry: Approved scanner inventory and change schedule; Service responses and vulnerability details; Endpoint process history

Possible false positive: An approved vulnerability scanner or an inventory tool.

Comparison: observed 20 unique TCP ports; threshold 12; earlier median 0.0. Median of earlier same-context buckets in this dataset, including zero recorded matches. Logging completeness and normal behavior are unknown; this comparison does not trigger the alert.

ATT&CK reference: [T1046 · Network Service Discovery](https://attack.mitre.org/techniques/T1046/). Behavior reference; not attribution.

Hypothesis, not observed: Attempted access to an exposed service. Look for subsequent connections and application or endpoint evidence; a scan does not prove exploitation.

Next checks: Verify the source owner and scanning schedule before escalating. Request Approved scanner inventory and change schedule; Service responses and vulnerability details; Endpoint process history. If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap.

## Example scope

This report uses the included synthetic sample. It contains deterministic rule context, not a live model response or a completed human assessment. Use the app to add your own review and export it.
