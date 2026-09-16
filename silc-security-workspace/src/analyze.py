from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.detections import run_all_detections
from src.validation import read_events

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data" / "network_events.csv"
ALERTS_OUTPUT = ROOT / "output" / "alerts.csv"
REPORT_OUTPUT = ROOT / "output" / "incident_report.md"


def load_events(path: Path = INPUT) -> pd.DataFrame:
    return read_events(path)


def build_report(events: pd.DataFrame, alerts: pd.DataFrame, synthetic: bool = True) -> str:
    severity_counts = alerts["severity"].value_counts().to_dict()
    lines = [
        "# SILC · Incident Analysis Report",
        "",
        "## Executive summary",
        "",
        f"The analysis pipeline processed **{len(events):,} network events** and generated "
        f"**{len(alerts):,} alerts** for analyst review.",
        "",
        ("Source: synthetic lab telemetry." if synthetic else "Source: user-uploaded CSV; provenance not independently verified."),
        "An alert indicates evidence worth investigating, not confirmed malicious activity.",
        "",
        "## Alert totals",
        "",
    ]
    for severity in ["Critical", "High", "Medium", "Low"]:
        lines.append(f"- {severity}: {severity_counts.get(severity, 0)}")
    lines.extend(["", "## Prioritized findings", ""])
    lines.extend([f"Showing up to 100 prioritized findings out of {len(alerts)} total alerts.", ""])
    for index, row in alerts.head(100).iterrows():
        lines.extend([
            f"### {index + 1}. {row['alert_type']} - {row['severity']}",
            "",
            f"- Source: `{row['source_ip']}`",
            f"- Alert ID: {row['alert_id']}",
            f"- Matching events: {row['event_count']}",
            f"- First/last seen (UTC): {row['first_seen']} / {row['last_seen']}",
            f"- Destination: `{row['destination_ip']}`",
            f"- Evidence: {row['evidence']}",
            f"- Recommended action: {row['recommendation']}",
            "",
        ])
    lines.extend([
        "## Analyst decision",
        "",
        "Validate each finding against asset ownership, approved activity, authentication history, and surrounding telemetry before escalation or containment.",
    ])
    return "\n".join(lines)


def main() -> None:
    events = load_events()
    alerts = run_all_detections(events)
    ALERTS_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    alerts.drop(columns=["_evidence_ids"]).to_csv(ALERTS_OUTPUT, index=False)
    REPORT_OUTPUT.write_text(build_report(events, alerts), encoding="utf-8")
    print(f"Analyzed {len(events):,} events and created {len(alerts):,} alerts.")
    print(f"Alerts: {ALERTS_OUTPUT}")
    print(f"Report: {REPORT_OUTPUT}")


if __name__ == "__main__":
    main()
