"""Evidence explanations and correlation. No model is needed and no actions are executed."""
from __future__ import annotations

import hashlib
from datetime import timedelta
import pandas as pd

from src.rules import RULES
from src.config import BRUTE_FORCE_FAILURES, PORT_SCAN_UNIQUE_PORTS, SYN_FLOOD_PACKETS

BY_TYPE = {r["type"]: r for r in RULES}
REFERENCE = {
    "Possible brute force": ("T1110.001", "Password Guessing", "https://attack.mitre.org/techniques/T1110/001/", "Behavior reference"),
    "Port scan": ("T1046", "Network Service Discovery", "https://attack.mitre.org/techniques/T1046/", "Behavior reference"),
    "Possible SYN flood": ("T1498.001", "Direct Network Flood", "https://attack.mitre.org/techniques/T1498/001/", "Behavior reference"),
    "Suspicious DNS query": ("T1071.004", "Application Layer Protocol: DNS", "https://attack.mitre.org/techniques/T1071/004/", "Hypothesis only; C2 is not established"),
    "Suspicious HTTP redirect": ("T1189", "Drive-by Compromise", "https://attack.mitre.org/techniques/T1189/", "Hypothesis only; browser exploitation is not established"),
}
MISSING = {
    "Possible brute force": ["Account ownership and authorized source inventory", "Identity-provider session and MFA records", "Endpoint process history"],
    "Port scan": ["Approved scanner inventory and change schedule", "Service responses and vulnerability details", "Endpoint process history"],
    "Possible SYN flood": ["Completed TCP handshakes and retransmissions", "Service health and availability measurements", "Historical traffic baseline and load-test schedule"],
    "Suspicious DNS query": ["Validated indicator provenance and current reputation", "DNS response and connection outcomes", "Endpoint process and command-and-control evidence"],
    "Suspicious HTTP redirect": ["Full browser/proxy redirect chain", "Download, execution and endpoint telemetry", "Validated indicator provenance"],
}
HYPOTHESES = {
    "Possible brute force": ("Unauthorized account access", "Check for later successful authentication and confirm whether the account owner recognizes it."),
    "Port scan": ("Attempted access to an exposed service", "Look for subsequent connections and application or endpoint evidence; a scan does not prove exploitation."),
    "Possible SYN flood": ("Service disruption", "Compare availability and completed handshakes before concluding that a denial of service occurred."),
    "Suspicious DNS query": ("Follow-on connection to the resolved destination", "Correlate DNS responses with proxy and endpoint telemetry; a query alone is not C2."),
    "Suspicious HTTP redirect": ("Untrusted download or browser exploitation", "Seek download and execution records; a redirect alone does not establish either outcome."),
}


def fingerprint(events):
    canonical = events.sort_values("event_id").to_csv(index=False).encode()
    return hashlib.sha256(canonical).hexdigest()


def public_alert(alert, digest):
    a = {k: v for k, v in dict(alert).items() if not k.startswith("_")}
    r = BY_TYPE[a["alert_type"]]
    reference = REFERENCE[a["alert_type"]]
    a.update(case_id="INC-" + digest[:8].upper() + "-" + a["alert_id"][4:10],
             rule_id=r["id"], detection_confidence="Indicator only" if r["id"] in {"DNS-01", "WEB-01"} else "Pattern supported",
             evidence_quality="Partial telemetry", technique={"id": reference[0], "name": reference[1], "url": reference[2], "basis": reference[3]})
    return a


def event_links(alerts):
    links = {}
    for a in alerts.to_dict(orient="records"):
        for event_id in a.get("_evidence_ids", a["evidence_ids"]):
            links.setdefault(event_id, []).append(a["alert_id"])
    return links


def records(frame):
    result = frame.copy()
    result["timestamp"] = result["timestamp"].map(lambda t: t.isoformat())
    return result.to_dict(orient="records")


def comparison(events, alert, matched):
    """Use earlier comparable buckets in THIS dataset, never claim a normal baseline."""
    kind = alert["alert_type"]
    defaults = {"available": False, "label": "Dataset comparison", "median": None,
                "observed": None, "threshold": None, "earlier_buckets": 0,
                "note": "No historical normal baseline is provided by this dataset."}
    if kind not in {"Possible brute force", "Port scan", "Possible SYN flood"}:
        return {**defaults, "note": "This is an exact indicator match, not a baseline anomaly test.", "unit": "indicator matches", "observed": int(alert["event_count"])}
    pair = events[(events["source_ip"] == alert["source_ip"]) & (events["destination_ip"] == alert["destination_ip"])].copy()
    period = "1min" if kind == "Possible SYN flood" else "5min"
    interval = timedelta(minutes=1 if kind == "Possible SYN flood" else 5)
    if kind == "Possible brute force":
        pair = pair[(pair["auth_result"] == "failure") & (pair["username"] == matched.iloc[0]["username"])]
        threshold, unit, observed = BRUTE_FORCE_FAILURES, "failed logins", len(matched)
    elif kind == "Port scan":
        pair = pair[pair["protocol"] == "TCP"]
        threshold, unit, observed = PORT_SCAN_UNIQUE_PORTS, "unique TCP ports", matched["destination_port"].nunique()
    else:
        pair = pair[(pair["protocol"] == "TCP") & (pair["tcp_flags"] == "SYN") & (pair["destination_port"] == matched.iloc[0]["destination_port"])]
        threshold, unit, observed = SYN_FLOOD_PACKETS, "SYN records", len(matched)
    start = pd.Timestamp(alert["first_seen"]).floor(period)
    first = events["timestamp"].min().ceil(period)
    earlier = pd.date_range(first, start - interval, freq=period)
    result = {**defaults, "observed": int(observed), "threshold": threshold, "unit": unit,
              "bucket_start": start.isoformat(), "bucket_end": (start + interval).isoformat()}
    if not len(earlier):
        return {**result, "note": "No earlier complete same-context buckets exist in this dataset. Only the configured threshold can be compared."}
    before = pair[pair["timestamp"] < start].copy()
    before["bucket"] = before["timestamp"].dt.floor(period)
    grouped = before.groupby("bucket")["destination_port"].nunique() if kind == "Port scan" else before.groupby("bucket").size()
    median = float(grouped.reindex(earlier, fill_value=0).median())
    return {**result, "available": True, "median": median, "earlier_buckets": len(earlier),
            "note": "Median of earlier same-context buckets in this dataset, including zero recorded matches. Logging completeness and normal behavior are unknown; this comparison does not trigger the alert."}


def context(item, alert):
    a = public_alert(alert, item["fingerprint"])
    r = BY_TYPE[a["alert_type"]]
    ids = alert.get("_evidence_ids", alert["evidence_ids"])
    matched = item["events"][item["events"]["event_id"].isin(ids)].sort_values("timestamp")
    compare = comparison(item["events"], a, matched)
    step_title, step_check = HYPOTHESES[a["alert_type"]]
    window_start = pd.Timestamp(a["first_seen"]) - timedelta(minutes=15)
    window_end = pd.Timestamp(a["last_seen"]) + timedelta(minutes=15)
    hosts = {a["source_ip"], a["destination_ip"]}
    related_mask = ((item["events"]["source_ip"].isin(hosts) | item["events"]["destination_ip"].isin(hosts)) & item["events"]["timestamp"].between(window_start, window_end))
    neighbors = item["events"][related_mask & ~item["events"]["event_id"].isin(ids)].sort_values("timestamp")
    related = []
    for other in item["alerts"].to_dict(orient="records"):
        if other["alert_id"] == a["alert_id"]:
            continue
        if ({other["source_ip"], other["destination_ip"]} & hosts and
            pd.Timestamp(other["first_seen"]) <= window_end and pd.Timestamp(other["last_seen"]) >= window_start):
            related.append(public_alert(other, item["fingerprint"]))
    graph_rows = item["events"][related_mask]
    grouped = graph_rows.groupby(["source_ip", "destination_ip"]).size().sort_values(ascending=False)
    edges = [{"source": a["source_ip"], "target": a["destination_ip"], "events": int(((graph_rows["source_ip"] == a["source_ip"]) & (graph_rows["destination_ip"] == a["destination_ip"])).sum())}]
    for (source, destination), count in grouped.items():
        if (source, destination) != (a["source_ip"], a["destination_ip"]):
            edges.append({"source": source, "target": destination, "events": int(count)})
        if len(edges) >= 6:
            break
    preview = records(matched[matched["event_id"].isin(a["evidence_ids"])])
    surrounding = records(neighbors.head(50))
    for row in preview + surrounding:
        row["alert_ids"] = item["event_links"].get(row["event_id"], [])
    return {
        "alert": a, "rule": r, "case_id": a["case_id"],
        "reasoning": {
            "source": "Deterministic rule explanation", "why_flagged": r["why"], "observed": a["evidence"],
            "rule_trigger": r["logic"], "detection_confidence": a["detection_confidence"],
            "confidence_note": "Describes support for a rule match, not the probability of an attack. Maliciousness confidence has not been measured.",
            "evidence_quality": "Partial telemetry", "evidence_available": len(matched), "preview_shown": min(100, len(matched)),
            "missing_telemetry": MISSING[a["alert_type"]], "false_positives": [r["false_positive"]],
            "limitations": [r["limit"], "A CSV cannot establish authorization, causality, service impact or collection completeness."],
            "comparison": compare, "technique": a["technique"],
        },
        "evidence": preview,
        "related_events": surrounding, "related_events_total": len(neighbors),
        "related_alerts": related[:10], "related_alerts_total": len(related),
        "correlation_note": "Shared source or destination within 15 minutes of this finding. Proximity is not proof of causation or a shared attacker.",
        "graph": {"edges": edges, "total_connections": len(grouped), "label": "Observed CSV connections in the correlation window"},
        "attack_path": [
            {"kind": "observed", "title": a["alert_type"], "description": a["evidence"], "evidence_ids": a["evidence_ids"][:5]},
            {"kind": "hypothesis", "title": step_title, "description": step_check, "confidence": "Not assessed", "source": "Rule playbook; not an AI prediction"},
        ],
        "next_steps": [
            {"id": "verify", "title": "Verify the context", "why": r["next_check"]},
            {"id": "collect", "title": "Collect missing evidence", "why": "Request " + "; ".join(MISSING[a["alert_type"]]) + "."},
            {"id": "decide", "title": "Record your decision", "why": "If evidence supports unauthorized activity, follow your organization's escalation process. If authorized, document the benign explanation. If unclear, record the evidence gap."},
        ],
        "business_impact": "Possible " + step_title.lower() + "; actual impact and affected business criticality are not established by these logs.",
    }


def ai_context(item, alert):
    c = context(item, alert)
    return {**c["alert"], "reasoning": c["reasoning"], "next_steps": c["next_steps"], "attack_path": c["attack_path"]}


def context_report(item, limit=100):
    lines = ["\n## Reasoning and investigation context", "Detection confidence describes rule support. It is not calibrated attack probability."]
    for a in item["alerts"].head(limit).to_dict(orient="records"):
        c = context(item, a)
        r, b = c["reasoning"], c["reasoning"]["comparison"]
        lines += [f"\n### {c['case_id']} · {a['alert_id']}", f"Observed: {r['observed']}",
                  f"Why flagged: {r['why_flagged']}", f"Rule: {r['rule_trigger']}",
                  f"Detection confidence: {r['detection_confidence']}. {r['confidence_note']}",
                  f"Evidence quality: {r['evidence_quality']}; {r['evidence_available']} matching rows available.",
                  "Missing telemetry: " + "; ".join(r["missing_telemetry"]),
                  "Possible false positive: " + "; ".join(r["false_positives"]),
                  f"Comparison: observed {b['observed']} {b['unit']}; threshold {b['threshold']}; earlier median {b['median']}. {b['note']}",
                  f"ATT&CK reference: [{r['technique']['id']} · {r['technique']['name']}]({r['technique']['url']}). {r['technique']['basis']}; not attribution.",
                  "Hypothesis, not observed: " + c["attack_path"][1]["title"] + ". " + c["attack_path"][1]["description"],
                  "Next checks: " + " ".join(s["why"] for s in c["next_steps"])]
    return "\n\n".join(lines)
