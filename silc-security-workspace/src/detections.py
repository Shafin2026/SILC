from __future__ import annotations

import hashlib
import pandas as pd

from src.config import (
    BRUTE_FORCE_FAILURES,
    PORT_SCAN_UNIQUE_PORTS,
    SEVERITY_SCORES,
    SUSPICIOUS_DOMAINS,
    SYN_FLOOD_PACKETS,
)


ALERT_COLUMNS = [
    "alert_id", "event_count", "evidence_ids",
    "alert_type", "severity", "risk_score", "first_seen", "last_seen",
    "source_ip", "destination_ip", "evidence", "recommendation", "_evidence_ids",
]


def _alert(alert_type: str, severity: str, group: pd.DataFrame, evidence: str,
           recommendation: str) -> dict[str, object]:
    event_ids = sorted(group["event_id"].astype(str).tolist())
    signature = alert_type + "|" + "|".join(event_ids)
    return {
        "alert_id": "ALT-" + hashlib.sha256(signature.encode()).hexdigest()[:10].upper(),
        "event_count": len(group),
        "evidence_ids": event_ids[:100],
        "_evidence_ids": event_ids,
        "alert_type": alert_type,
        "severity": severity,
        "risk_score": SEVERITY_SCORES[severity],
        "first_seen": group["timestamp"].min().isoformat(),
        "last_seen": group["timestamp"].max().isoformat(),
        "source_ip": group.iloc[0]["source_ip"],
        "destination_ip": group.iloc[0]["destination_ip"],
        "evidence": evidence,
        "recommendation": recommendation,
    }


def detect_brute_force(frame: pd.DataFrame) -> list[dict[str, object]]:
    failures = frame[frame["auth_result"] == "failure"].copy()
    if failures.empty:
        return []
    failures["window"] = failures["timestamp"].dt.floor("5min")
    alerts = []
    for (source, destination, username, _), group in failures.groupby(
        ["source_ip", "destination_ip", "username", "window"]
    ):
        if len(group) >= BRUTE_FORCE_FAILURES:
            alerts.append(_alert(
                "Possible brute force", "High", group,
                f"{len(group)} failed logins for {username or 'unknown user'} within 5 minutes",
                "Check for later successful logins and verify the account owner. If unauthorized, escalate and consider approved account protection measures.",
            ))
    return alerts


def detect_port_scan(frame: pd.DataFrame) -> list[dict[str, object]]:
    tcp = frame[frame["protocol"] == "TCP"].copy()
    tcp["window"] = tcp["timestamp"].dt.floor("5min")
    alerts = []
    for (source, destination, _), group in tcp.groupby(["source_ip", "destination_ip", "window"]):
        ports = group["destination_port"].nunique()
        if ports >= PORT_SCAN_UNIQUE_PORTS:
            alerts.append(_alert(
                "Port scan", "Medium", group,
                f"{ports} unique destination ports contacted within 5 minutes",
                "Verify whether this is an approved vulnerability scanner. Correlate firewall logs and escalate unauthorized reconnaissance.",
            ))
    return alerts


def detect_syn_flood(frame: pd.DataFrame) -> list[dict[str, object]]:
    syn = frame[(frame["protocol"] == "TCP") & (frame["tcp_flags"] == "SYN")].copy()
    syn["window"] = syn["timestamp"].dt.floor("1min")
    alerts = []
    for (source, destination, port, _), group in syn.groupby(
        ["source_ip", "destination_ip", "destination_port", "window"]
    ):
        if len(group) >= SYN_FLOOD_PACKETS:
            alerts.append(_alert(
                "Possible SYN flood", "Critical", group,
                f"{len(group)} SYN packets targeted port {port} within 1 minute",
                "Check handshake completion, service health, and baseline traffic. Preserve evidence; consider rate limiting only through an approved response process.",
            ))
    return alerts


def detect_suspicious_domains(frame: pd.DataFrame) -> list[dict[str, object]]:
    alerts = []
    dns = (frame["protocol"] == "DNS") & frame["dns_query"].isin(SUSPICIOUS_DOMAINS)
    redirects = ((frame["protocol"] == "HTTP") & frame["http_status"].between(300, 399)
                 & frame["redirect_domain"].isin(SUSPICIOUS_DOMAINS))
    for mask, alert_type, column in [
        (dns, "Suspicious DNS query", "dns_query"),
        (redirects, "Suspicious HTTP redirect", "redirect_domain"),
    ]:
        for index in frame.index[mask]:
            group = frame.loc[[index]]
            domain = frame.loc[index, column]
            alerts.append(_alert(
                alert_type, "High", group,
                f"Exact match to a lab-only indicator: {domain}",
                "Correlate DNS, proxy, and endpoint history. In this lab the indicator is synthetic; a domain match alone does not prove compromise.",
            ))
    return alerts


def run_all_detections(frame: pd.DataFrame) -> pd.DataFrame:
    alerts = (
        detect_brute_force(frame)
        + detect_port_scan(frame)
        + detect_syn_flood(frame)
        + detect_suspicious_domains(frame)
    )
    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    return pd.DataFrame(alerts)[ALERT_COLUMNS].sort_values(
        ["risk_score", "first_seen"], ascending=[False, True]
    ).reset_index(drop=True)
