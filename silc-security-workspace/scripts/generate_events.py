from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "network_events.csv"
TOTAL_EVENTS = 11_000
SEED = 20260912


def make_event(timestamp: datetime, event_id: int, rng: random.Random) -> dict[str, object]:
    protocols = ["TCP", "UDP", "DNS", "HTTP", "ICMP"]
    protocol = rng.choices(protocols, weights=[48, 15, 18, 14, 5], k=1)[0]
    destination_port = rng.choice([22, 53, 80, 443, 445, 3389])
    if protocol == "DNS":
        destination_port = 53
    elif protocol == "HTTP":
        destination_port = rng.choice([80, 443])

    return {
        "event_id": f"EVT-{event_id:05d}",
        "timestamp": timestamp.isoformat(),
        "source_ip": f"10.0.{rng.randint(1, 20)}.{rng.randint(2, 250)}",
        "destination_ip": f"172.16.0.{rng.randint(2, 80)}",
        "source_port": rng.randint(1024, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "tcp_flags": "SYN" if protocol == "TCP" and rng.random() < 0.20 else "ACK",
        "action": rng.choices(["allowed", "blocked"], weights=[96, 4], k=1)[0],
        "username": rng.choice(["", "analyst", "jsmith", "service_backup", "admin"]),
        "auth_result": rng.choices(["", "success", "failure"], weights=[75, 22, 3], k=1)[0],
        "dns_query": "intranet.example" if protocol == "DNS" else "",
        "http_status": rng.choice([200, 200, 200, 404]) if protocol == "HTTP" else "",
        "redirect_domain": "",
        "bytes_sent": rng.randint(64, 8000),
    }


def inject_scenarios(events: list[dict[str, object]], start: datetime) -> None:
    # Brute force: 12 failures from one source within five minutes.
    for i in range(100, 112):
        events[i].update(
            timestamp=(start + timedelta(minutes=20, seconds=(i - 100) * 15)).isoformat(),
            source_ip="203.0.113.45",
            destination_ip="172.16.0.10",
            destination_port=22,
            protocol="TCP",
            username="admin",
            auth_result="failure",
        )

    # Port scan: one source touches 20 ports within five minutes.
    for offset, i in enumerate(range(700, 720)):
        events[i].update(
            timestamp=(start + timedelta(hours=1, seconds=offset * 10)).isoformat(),
            source_ip="198.51.100.27",
            destination_ip="172.16.0.25",
            destination_port=20 + offset,
            protocol="TCP",
            tcp_flags="SYN",
        )

    # SYN flood: 85 SYN packets in one minute.
    for offset, i in enumerate(range(2_000, 2_085)):
        events[i].update(
            timestamp=(start + timedelta(hours=2, seconds=offset % 55)).isoformat(),
            source_ip="192.0.2.88",
            destination_ip="172.16.0.50",
            destination_port=443,
            protocol="TCP",
            tcp_flags="SYN",
        )

    # Suspicious DNS queries.
    for offset, i in enumerate(range(4_000, 4_006)):
        events[i].update(
            timestamp=(start + timedelta(hours=3, minutes=offset)).isoformat(),
            source_ip="10.0.7.77",
            destination_ip="172.16.0.53",
            destination_port=53,
            protocol="DNS",
            dns_query="credential-check.example",
        )

    # Malicious redirect.
    events[8_000].update(
        timestamp=(start + timedelta(hours=4)).isoformat(),
        source_ip="10.0.4.22",
        destination_ip="172.16.0.30",
        destination_port=80,
        protocol="HTTP",
        http_status=302,
        redirect_domain="greatrecipesforme.example",
    )


def main() -> None:
    rng = random.Random(SEED)
    start = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
    events = [
        make_event(start + timedelta(seconds=i * 2), i + 1, rng)
        for i in range(TOTAL_EVENTS)
    ]
    inject_scenarios(events, start)
    # Remove unrelated random fields after injecting each scenario.
    for event in events:
        if event["protocol"] != "DNS":
            event["dns_query"] = ""
        if event["protocol"] != "HTTP":
            event["http_status"] = ""
            event["redirect_domain"] = ""
        if event["protocol"] != "TCP":
            event["tcp_flags"] = ""
            event["auth_result"] = ""
            event["username"] = ""
    events.sort(key=lambda event: str(event["timestamp"]))

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(events[0]))
        writer.writeheader()
        writer.writerows(events)
    print(f"Created {len(events):,} events at {OUTPUT}")


if __name__ == "__main__":
    main()
